Feature: Orchestrator lifecycle (spec/002 — RETROSPECTIVE)

  # Covers: REQ-200, REQ-201, REQ-202, REQ-203, REQ-204, REQ-205, REQ-206, REQ-207, REQ-208, REQ-209, REQ-210, REQ-211, REQ-212, REQ-213, REQ-214, REQ-215

  Scenario: Orchestrator constructed via NewOrchestrator
    When NewOrchestrator(OrchestratorConfig{DB: db, Config: cfg, ...}) is called
    Then a valid *Orchestrator is returned
    And o.swarm, o.docker, o.npm, o.pihole, o.ports, o.hal are all initialised

  Scenario: NewOrchestrator returns error on nil DB
    When NewOrchestrator(OrchestratorConfig{DB: nil, Config: cfg}) is called
    Then error "database connection required" is returned

  Scenario: PortManager triple-source initialisation
    When NewOrchestrator constructs
    Then NewPortManager(cfg.DB, o.swarm, cfg.HALClient) is called

  Scenario: SetFlowEngine late-binds engine
    Given Orchestrator was constructed before engine.Start()
    When orchestrator.SetFlowEngine(engine, store) is called
    Then o.engine = engine and o.feStore = store

  Scenario: Close cancels context + closes docker
    Given Orchestrator is running
    When Close() is called
    Then o.cancel is invoked
    And o.docker.Close() is invoked
    And nil error returned

  Scenario: StartApp delegates to Swarm OR Docker based on app.UsesSwarm
    Given app "uptime-kuma" has UsesSwarm == true
    When orchestrator.StartApp(ctx, "uptime-kuma") is called
    Then swarm.DeployStack is invoked
    And docker.StartContainer is NOT invoked

  Scenario: StopApp scales Swarm to 0 (not removes stack)
    Given app "uptime-kuma" has UsesSwarm == true
    When orchestrator.StopApp(ctx, "uptime-kuma") is called
    Then swarm.ScaleService(name+"_"+name, 0) is invoked

  Scenario: SetProfileApp uses INSERT...ON CONFLICT
    When orchestrator.SetProfileApp(ctx, 1, 42, true) is called
    Then the SQL INSERT INTO profile_apps (...) ON CONFLICT (profile_id, app_id) DO UPDATE SET enabled = excluded.enabled runs

  Scenario: Orchestrator has NO direct InstallApp method
    When developer inspects internal/managers/orchestrator.go
    Then no method InstallApp(ctx, ...) is defined on Orchestrator
    And install flow goes through engine.Submit(ctx, SubmitParams{WorkflowType: "appstore_install", ...})

  Scenario: NPM init failure logs warning + continues
    Given NPM is unreachable at NewOrchestrator time
    When NPM Init returns error
    Then log.Warn is called with the error
    And NewOrchestrator returns *Orchestrator without error
