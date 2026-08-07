Feature: Contribute
  As a security engineer
  I want to contribute local package manifest analysis to Sentinel Cloud content intelligence
  So that the Cloud seeds shared knowledge about package supply chain signals

  Background:
    Given Sentinel Cloud is reachable at a known base URL
    And an active session with the contribute capability

  Scenario: Contribution of a malicious manifest succeeds
    Given a package.json with a malicious postinstall script
    And the Cloud accepts the contribution
    When I run "sentinel contribute <path>"
    Then it exits 0
    And the output contains "Contribution recorded"
    And the output contains "State: MALICIOUS"
    And the output contains "Verified: false"

  Scenario: Contribution downgraded and not applied
    Given a package.json with a malicious postinstall script
    And the Cloud returns applied false with reason "downgrade-rejected"
    When I run "sentinel contribute <path>"
    Then it exits 0
    And the output contains "Contribution not applied"
    And the output contains "downgrade-rejected"

  Scenario: Contribute with --json
    Given a valid package.json
    And the Cloud accepts the contribution
    When I run "sentinel contribute <path> --json"
    Then it exits 0
    And the raw Cloud contribution result is printed as JSON

  Scenario: No active session
    Given no session file exists
    When I run "sentinel contribute <path>"
    Then it exits 1
    And the output contains "No active session. Run 'sentinel login' first."

  Scenario: Plan without intelligence contribution
    Given an active session without the contribute capability
    When I run "sentinel contribute <path>"
    Then it exits 1
    And the output contains "Your plan does not include intelligence contribution."
    And no request is sent to the Cloud

  Scenario: Invalid token
    Given an active session
    And the Cloud rejects the request with 401
    When I run "sentinel contribute <path>"
    Then it exits 1
    And the session file is cleared
    And the output contains "Session expired. Run 'sentinel login'."

  Scenario: Cloud limit reached
    Given an active session
    And the Cloud rejects the request with 429 and Retry-After 60
    When I run "sentinel contribute <path>"
    Then it exits 1
    And the output contains "Cloud limit reached (quota or rate)."
    And the output contains "Retry in 60s."

  Scenario: Content intelligence disabled
    Given an active session
    And the Cloud responds with 503
    When I run "sentinel contribute <path>"
    Then it exits 1
    And the output contains "Content intelligence is disabled on the Cloud."

  Scenario: Cloud unavailable
    Given an active session
    And the Cloud is unreachable or responds with a 5xx
    When I run "sentinel contribute <path>"
    Then it exits 0
    And the output contains "Cloud unavailable — continuing with local analysis."

  Scenario: Contribution rejected with a bad request
    Given an active session
    And the Cloud rejects the request with 400
    When I run "sentinel contribute <path>"
    Then it exits 1
    And the output contains "Contribution rejected:"

  Scenario: Manifest too large
    Given a package.json larger than 256KB
    When I run "sentinel contribute <path>"
    Then it exits 1
    And the output contains "Manifest too large (max 256KB)."

  Scenario: Path without package.json
    Given a directory that does not contain package.json
    When I run "sentinel contribute <path>"
    Then it exits 1
    And the output contains "No package.json found"

  Scenario: Unsupported format
    Given an active session
    When I run "sentinel contribute <path> --format yarn"
    Then it exits 1
    And the output contains "Unsupported format 'yarn'. Supported: ['npm']."
