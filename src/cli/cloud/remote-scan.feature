Feature: Remote scan
  As a security engineer
  I want to submit package manifests to the Sentinel Cloud engine
  So that I get an engine-level verdict before falling back to local analysis

  Background:
    Given Sentinel Cloud is reachable at a known base URL
    And an active session with the remote_scan capability

  Scenario: Remote scan of a malicious manifest succeeds
    Given a package.json with a malicious postinstall script
    And the Cloud engine responds with a complete MALICIOUS result
    When I run "sentinel remote-scan <path>"
    Then it exits 0
    And the output contains "Verdict: MALICIOUS"
    And the output contains the risk score and confidence

  Scenario: Remote scan with --json
    Given a valid package.json
    And the Cloud engine responds with a complete result
    When I run "sentinel remote-scan <path> --json"
    Then it exits 0
    And the raw Cloud result is printed as JSON

  Scenario: No active session
    Given no session file exists
    When I run "sentinel remote-scan <path>"
    Then it exits 1
    And the output contains "No active session. Run 'sentinel login' first."

  Scenario: Plan without remote scanning
    Given an active session without the remote_scan capability
    When I run "sentinel remote-scan <path>"
    Then it exits 1
    And the output contains "Your plan does not include remote scanning."
    And no request is sent to the Cloud

  Scenario: Invalid token
    Given an active session
    And the Cloud rejects the request with 401
    When I run "sentinel remote-scan <path>"
    Then it exits 1
    And the session file is cleared
    And the output contains "Session expired. Run 'sentinel login'."

  Scenario: Quota exceeded
    Given an active session
    And the Cloud rejects the request with 429
    When I run "sentinel remote-scan <path>"
    Then it exits 1
    And the output contains "Cloud limit reached (quota or rate). Retry later."

  Scenario: Scan engine busy
    Given an active session
    And the Cloud responds with 503
    When I run "sentinel remote-scan <path>"
    Then it exits 1
    And the output contains "Scan engine is busy. Retry shortly."

  Scenario: Cloud offline
    Given an active session
    And the Cloud is unreachable or responds with a 5xx
    When I run "sentinel remote-scan <path>"
    Then it exits 0
    And the output contains "Cloud scan unavailable — continuing with local analysis."

  Scenario: Manifest too large
    Given a package.json larger than 256KB
    When I run "sentinel remote-scan <path>"
    Then it exits 1
    And the output contains "Manifest too large (max 256KB)."

  Scenario: Path without package.json
    Given a directory that does not contain package.json
    When I run "sentinel remote-scan <path>"
    Then it exits 1
    And the output contains "No package.json found"

  Scenario: Unsupported format
    Given an active session
    When I run "sentinel remote-scan <path> --format yarn"
    Then it exits 1
    And the output contains "Unsupported format 'yarn'. Supported: ['npm']."
