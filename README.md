# Ego
![Ego Logo](https://codeeras.gallerycdn.vsassets.io/extensions/codeeras/ego-go/1.2.0/1738078515541/Microsoft.VisualStudio.Services.Icons.Small)

## Project Description
Ego is a dynamic debugging library designed to help developers troubleshoot production issues with minimal performance impact. 
It enables real-time monitoring and logging of function arguments and return values with only the library imported. 
Ego is designed to be lightweight and easy to integrate into existing projects, providing powerful debugging capabilities without significant overhead.

## Features
- Dynamic logging, tracing and monitoring


## Usage
### Import Package from Package main

Example:
```go
package main

import (
	"fmt"
	"math/rand"
	"time"

	_ "github.com/CoverConnect/ego/cmd/ego"
)

func main() {
	

	go func() {
		for {
			v := rand.Intn(10)
			v2 := rand.Intn(10)
			simpleInt(v, v2)
			time.Sleep(3 * time.Second)
		}
	}()

	for {
		fmt.Print(".")
		time.Sleep(10 * time.Second)
	}
}
```

### Use Ego VScode Extension

Download the Plugin [ego](https://marketplace.visualstudio.com/items?itemName=CodeEras.ego-go&ssr=false#overview)


## License
This project is licensed under the MIT License - see the [LICENSE](https://github.com/CoverConnect/ego/blob/main/LICENSE) file for details.

## Contact
For any inquiries or support, please raise an issue.

