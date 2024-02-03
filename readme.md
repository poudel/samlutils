# saml utils

## IDP metadata parsing

```go
package main

import (
	"fmt"
	"github.com/poudel/samlutils"
)

func main() {
	m := samlutils.ParseIdpMetadata(samlutils.EXAMPLE_OKTA_METADATA)
	fmt.Println("Valid:", m.IsValid())
	fmt.Println("Metadata:", m)
}
```
