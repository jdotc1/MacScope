# Network evidence core

`NetworkEvidenceCore` is a dependency-free Swift package target (Foundation and CryptoKit only)
that holds the pure evidence model for relating observed network traffic to static code candidates.

## Contents

| Area | Responsibility |
|---|---|
| Investigation models | Workspace identity, static endpoint candidates, call edges, runtime references, correlation findings and hypotheses, closed error and digest helpers |
| Flow models | Minimized flow reference, summary and detail, observation limitations, recording and knowledge states |
| Privacy | Route, field-name, media-type, host and source-name minimization shared by captured and static data |
| Endpoint extraction | Interprets one binary string as host, path, scheme and port; never retains query values, fragments or user-info |
| Correlation engine | Matches static candidates to observed flows, grades each association, and states what it does not prove |

Correlation is heuristic. A match is a candidate association, never proof that a function executed or
that a response value reached code.

## Build and tests

~~~sh
swift build
swift test
~~~

There are no remote dependencies and nothing to resolve. Swift tools 6.0 and Swift 6 language
mode are used, with the same macOS baseline as the app.
