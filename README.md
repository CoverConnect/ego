# Ego
![Ego Logo](https://codeeras.gallerycdn.vsassets.io/extensions/codeeras/ego-go/1.2.0/1738078515541/Microsoft.VisualStudio.Services.Icons.Small)


This extension provides a user interface for [EGO](https://github.com/CoverConnect/ego), a Golang non-stop debugging library.

# Purpose
Ego is a dynamic debugging library designed to help developers troubleshoot production issues with minimal performance impact. 
It enables real-time monitoring and logging of function arguments and return values with only the library imported. 

# Features
- **Non-stop LogPoint**: Set breakpoints without stopping the application.
- **Function level Tracing**: Trace specific functions to monitor their execution. (<span style="color: purple;">Under Construction</span>)
- **Package Tracing**: Trace entire packages to get a comprehensive view of the application's behavior.
- **Dynamic Log View**: View logs dynamically in a webview.
- **Trace Backend Connection**: Connect to a trace backend to visualize and analyze traces.


# Getting Started
### 1. **Import the ego instrument library**
  ```go
  import (
    "math/rand"
    "time"

    _ "github.com/CoverConnect/ego/cmd/ego"
  )
  ```

### 2. **Install the Extension**
 Install the [EGO extension](https://marketplace.visualstudio.com/items?itemName=CodeEras.ego-go) from the VS Code marketplace.


### 3. Set a function argument logpoint

![Ego logpoint](https://raw.githubusercontent.com/backman-git/ego-resource/refs/heads/main/demo.gif)






## Commands

- `EGO: Show Trace View`: Show the trace view panel. (<span style="color: purple;">Under Construction</span>)
- `EGO: Refresh Trace Backend`: Refresh the trace backend view. (<span style="color: purple;">Under Construction</span>)
- `EGO: Connect Trace Backend`: Connect to a trace backend. (<span style="color: purple;">Under Construction</span>)
- `EGO: Refresh Process View`: Refresh the traced process view.
- `EGO: Refresh Function View`: Refresh the traced functions view.

