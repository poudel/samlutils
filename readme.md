# saml utils

## IDP metadata parsing

```go
package main

import (
    "github.com/poudel/samlutils"
)

m := ParseIdpMetadata(metadata_string)
fmt.Println("Valid: %q", m.IsValid())
fmt.Println("Metadata: %q", m)
```
