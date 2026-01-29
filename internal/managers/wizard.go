package managers

import (
	"context"
	"sort"
	"time"

	"cubeos-api/internal/config"
	"cubeos-api/internal/models"
)

// WizardManager handles setup wizard operations
type WizardManager struct {
	cfg    *config.Config
	docker *DockerManager
}

// NewWizardManager creates a new WizardManager
func NewWizardManager(cfg *config.Config, docker *DockerManager) *WizardManager {
	return &WizardManager{cfg: cfg, docker: docker}
}

// UseCaseProfile represents a predefined configuration profile
type UseCaseProfile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Services    []string `json:"services"`
	RAMEstimate int      `json:"ram_estimate_mb"`
}

// Predefined use case profiles
var UseCaseProfiles = map[string]UseCaseProfile{
	"minimal": {
		ID:          "minimal",
		Name:        "Minimal",
		Description: "Essential services only - Wikipedia, maps, basic tools",
		Services:    []string{"kiwix", "tileserver", "it-tools"},
		RAMEstimate: 512,
	},
	"expedition": {
		ID:          "expedition",
		Name:        "Expedition Team",
		Description: "Knowledge, collaboration, and communication for field teams",
		Services: []string{
			"kiwix", "tileserver", "calibre-web", "emergency-ref",
			"cryptpad", "excalidraw", "filebrowser",
			"element", "conduit", "meshtastic-web",
		},
		RAMEstimate: 3072,
	},
	"sailing": {
		ID:          "sailing",
		Name:        "Sailing & Marine",
		Description: "Navigation, weather, marine data, and entertainment",
		Services: []string{
			"kiwix", "tileserver", "emergency-ref",
			"signalk-server", "meshtastic-web",
			"jellyfin", "calibre-web",
		},
		RAMEstimate: 2048,
	},
	"privacy": {
		ID:          "privacy",
		Name:        "Privacy-Focused",
		Description: "Secure communications and local AI without cloud dependencies",
		Services: []string{
			"ollama", "open-webui", "libretranslate",
			"vaultwarden", "cryptpad", "syncthing",
			"element", "conduit",
		},
		RAMEstimate: 5120,
	},
	"full": {
		ID:          "full",
		Name:        "Full Installation",
		Description: "All available services enabled",
		Services:    []string{}, // Populated dynamically
		RAMEstimate: 6500,
	},
}

// GetProfiles returns all available profiles
func (m *WizardManager) GetProfiles() []models.WizardProfile {
	var profiles []models.WizardProfile
	
	// Get all services for "full" profile
	allServices := m.docker.ListServices()
	var allServiceNames []string
	var totalRAM int
	
	for _, svc := range allServices {
		if !svc.IsCore {
			allServiceNames = append(allServiceNames, svc.Name)
			totalRAM += svc.RAMEstimateMB
		}
	}
	
	for id, profile := range UseCaseProfiles {
		services := profile.Services
		ramEstimate := profile.RAMEstimate
		
		if id == "full" {
			services = allServiceNames
			ramEstimate = totalRAM
		}
		
		// Get unique categories
		categories := make(map[string]bool)
		for _, svcName := range services {
			for _, svc := range allServices {
				if svc.Name == svcName {
					categories[svc.Category] = true
					break
				}
			}
		}
		
		var categoryList []string
		for cat := range categories {
			categoryList = append(categoryList, cat)
		}
		sort.Strings(categoryList)
		
		profiles = append(profiles, models.WizardProfile{
			ID:          id,
			Name:        profile.Name,
			Description: profile.Description,
			Services:    services,
			RAMEstimate: ramEstimate,
			Categories:  categoryList,
		})
	}
	
	// Sort profiles by RAM estimate
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].RAMEstimate < profiles[j].RAMEstimate
	})
	
	return profiles
}

// GetWizardServices returns services grouped by category
func (m *WizardManager) GetWizardServices() models.WizardServicesResponse {
	services := m.docker.ListServices()
	
	// Group by category
	byCategory := make(map[string][]models.WizardService)
	for _, svc := range services {
		if svc.IsCore {
			continue
		}
		
		wizardSvc := models.WizardService{
			Name:        svc.Name,
			DisplayName: svc.DisplayName,
			Description: svc.Description,
			RAMEstimate: svc.RAMEstimateMB,
			Icon:        svc.Icon,
			Enabled:     svc.Enabled,
		}
		
		byCategory[svc.Category] = append(byCategory[svc.Category], wizardSvc)
	}
	
	var categories []models.WizardCategory
	totalServices := 0
	
	for catID, catInfo := range config.Categories {
		svcs, ok := byCategory[catID]
		if !ok || len(svcs) == 0 {
			continue
		}
		
		categories = append(categories, models.WizardCategory{
			ID:          catID,
			Name:        catInfo.Name,
			Description: catInfo.Description,
			Icon:        catInfo.Icon,
			Services:    svcs,
		})
		
		totalServices += len(svcs)
	}
	
	// Sort categories by name
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Name < categories[j].Name
	})
	
	return models.WizardServicesResponse{
		Categories:    categories,
		TotalServices: totalServices,
	}
}

// ApplyProfile applies a use case profile
func (m *WizardManager) ApplyProfile(profileID string, additionalServices, excludedServices []string) models.ApplyProfileResponse {
	profile, ok := UseCaseProfiles[profileID]
	if !ok {
		return models.ApplyProfileResponse{
			Success: false,
			Message: "Unknown profile: " + profileID,
		}
	}
	
	// Build service list
	toEnable := make(map[string]bool)
	
	if profileID == "full" {
		// Enable all non-core services
		services := m.docker.ListServices()
		for _, svc := range services {
			if !svc.IsCore {
				toEnable[svc.Name] = true
			}
		}
	} else {
		for _, svc := range profile.Services {
			toEnable[svc] = true
		}
	}
	
	// Add additional services
	for _, svc := range additionalServices {
		toEnable[svc] = true
	}
	
	// Remove excluded services
	for _, svc := range excludedServices {
		delete(toEnable, svc)
	}
	
	// Get all toggleable services
	services := m.docker.ListServices()
	allToggleable := make(map[string]bool)
	for _, svc := range services {
		if !svc.IsCore {
			allToggleable[svc.Name] = true
		}
	}
	
	var enabled, disabled []string
	var totalRAM int
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	// Disable services not in toEnable
	for svcName := range allToggleable {
		if !toEnable[svcName] {
			if err := m.docker.StopContainer(ctx, svcName, 30); err == nil {
				disabled = append(disabled, svcName)
			}
		}
	}
	
	// Enable services in toEnable
	for svcName := range toEnable {
		if err := m.docker.StartContainer(ctx, svcName); err == nil {
			enabled = append(enabled, svcName)
			
			// Get RAM estimate
			for _, svc := range services {
				if svc.Name == svcName {
					totalRAM += svc.RAMEstimateMB
					break
				}
			}
		}
	}
	
	return models.ApplyProfileResponse{
		Success:          true,
		EnabledServices:  enabled,
		DisabledServices: disabled,
		TotalRAM:         totalRAM,
		Message:          "Profile applied successfully",
	}
}

// GetRecommendations returns service recommendations based on available RAM
func (m *WizardManager) GetRecommendations(availableRAM int) map[string]interface{} {
	services := m.docker.ListServices()
	
	// Sort by RAM usage
	sort.Slice(services, func(i, j int) bool {
		return services[i].RAMEstimateMB < services[j].RAMEstimateMB
	})
	
	// Find services that fit
	var fittingServices []string
	var totalRAM int
	headroom := int(float64(availableRAM) * 0.8) // Keep 20% headroom
	
	for _, svc := range services {
		if svc.IsCore {
			continue
		}
		if totalRAM+svc.RAMEstimateMB <= headroom {
			fittingServices = append(fittingServices, svc.Name)
			totalRAM += svc.RAMEstimateMB
		}
	}
	
	// Find best matching profile
	bestProfile := "minimal"
	bestMatch := 0
	
	for profileID, profile := range UseCaseProfiles {
		if profileID == "full" {
			continue
		}
		
		// Count matching services
		matchCount := 0
		fittingSet := make(map[string]bool)
		for _, s := range fittingServices {
			fittingSet[s] = true
		}
		
		for _, svc := range profile.Services {
			if fittingSet[svc] {
				matchCount++
			}
		}
		
		if matchCount > bestMatch && profile.RAMEstimate <= availableRAM {
			bestMatch = matchCount
			bestProfile = profileID
		}
	}
	
	return map[string]interface{}{
		"recommended_profile": bestProfile,
		"fitting_services":    fittingServices,
		"total_ram_mb":        totalRAM,
		"headroom_mb":         availableRAM - totalRAM,
		"message":             "Recommended profile '" + bestProfile + "'",
	}
}

// EstimateResources estimates resource usage for a list of services
func (m *WizardManager) EstimateResources(serviceNames []string) map[string]interface{} {
	services := m.docker.ListServices()
	
	var totalRAM int
	var found []string
	var missing []string
	
	serviceMap := make(map[string]models.ServiceInfo)
	for _, svc := range services {
		serviceMap[svc.Name] = svc
	}
	
	for _, name := range serviceNames {
		if svc, ok := serviceMap[name]; ok {
			totalRAM += svc.RAMEstimateMB
			found = append(found, name)
		} else {
			missing = append(missing, name)
		}
	}
	
	return map[string]interface{}{
		"services":         found,
		"missing_services": missing,
		"total_ram_mb":     totalRAM,
		"service_count":    len(found),
	}
}
