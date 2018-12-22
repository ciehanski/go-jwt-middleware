# Go JWT Middleware

This module lets you authenticate HTTP requests using [JWT]((http://jwt.io/)) tokens in your Golang applications. JWTs are typically used to protect API endpoints, and are often issued using OpenID Connect.

## Key Features

* Ability to **check the `Authorization` header, URL parameters & cookies** for a JWT
* **Decode, parse & validate** the JWT and set the content of it to the request context
* **Verify signing method** is not nil and valid
* Ability to parse JWTs with **custom claims**

## Installing

````bash
go get github.com/ciehanski/go-jwt-middleware
````

## Using it

[net/http](#nethttp)  
[negroni](#negroni)  
[martini](#martini)  
[gin](#gin)

## Options

````go
type Options struct {
  // The function that will return the Key to validate the JWT.
  // It can be either a shared secret or a public key.
  // Default value: nil
  ValidationKeyGetter jwt.Keyfunc
  // A boolean to ignore expiration of the JWT
  IgnoreExpiration bool
  // The name of the property in the request where the user information
  // from the JWT will be stored.
  // Default value: "user"
  UserProperty string
  // The function that will be called when there's an error validating the token
  // Default value: https://github.com/auth0/go-jwt-middleware/blob/master/jwtmiddleware.go#L35
  ErrorHandler ErrorHandler
  // A boolean indicating if the credentials are required or not
  // Default value: false
  CredentialsOptional bool
  // A function that extracts the token from the request
  // Default: FromAuthHeader (i.e., from Authorization header as bearer token)
  Extractor TokenExtractor
  // Debug flag turns on debugging output
  // Default: false  
  Debug bool
  // When set, all requests with the OPTIONS method will use authentication
  // Default: false
  EnableAuthOnOptions bool,
  // When set, the middleware verifies that tokens are signed with the specific signing algorithm
  // If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
  // Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
  // Default: nil
  SigningMethod jwt.SigningMethod
  // A function that creates custom jwt.Claims object
  // that passes to jwt.ParseWithClaims
  // Default: nil
  CustomClaims customClaims
}
````

The below functions are simple enough to implement yourself, so I saw no reason them to be exported.

```go
// customClaims is a function that returns custom jwt claims.
type customClaims func() jwt.Claims
// errorHandler is a handler function called whenever an error is encountered.
type errorHandler func(w http.ResponseWriter, r *http.Request, err error)
```

## Token Extraction

The default value for the `Extractor` option is the `FromAuthHeader`
function which assumes that the JWT will be provided as a bearer token
in an `Authorization` header, e.g.,

```
Authorization: bearer {token}
```

To extract the token from a query string parameter, you can use the
`FromParameter` function, e.g.,

```go
jwtmiddleware.New(jwtmiddleware.Options{
  Extractor: jwtmiddleware.FromParameter("auth_code"),
})
```

In this case, the `FromParameter` function will look for a JWT in the
`auth_code` query parameter of the URL.

Or, if you want to allow multiple methods of token extraction, you can use the `FromFirst` function to
try and extract the token first in one way and then in one or more
other ways, e.g.,

```go
jwtmiddleware.New(jwtmiddleware.Options{
  Extractor: jwtmiddleware.FromFirst(jwtmiddleware.FromAuthHeader,
                                     jwtmiddleware.FromParameter("auth_code")),
})
```

Lastly, you can also extract the JWT from a specified cookie name:
```go
jwtmiddleware.New(jwtmiddleware.Options{
  Extractor: jwtmiddleware.FromCookie("cookieName"),
})
```

## Examples

#### net/http
```go
package main

import ...

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  user := context.Get(r, "user")
  fmt.Fprintf(w, "This is an authenticated request")
  fmt.Fprintf(w, "Claim content:\n")
  for k, v := range user.(*jwt.Token).Claims.(jwt.MapClaims) {
    fmt.Fprintf(w, "%s :\t%#v\n", k, v)
  }
})

func main() {
  jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
    ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
      return []byte("dont-hack-me"), nil
    },
    // When set, the middleware verifies that tokens are signed with the specific signing algorithm
    // If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
    // Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
    SigningMethod: jwt.SigningMethodHS256,
  })

  app := jwtMiddleware.Handler(myHandler)
  http.ListenAndServe("0.0.0.0:3000", app)
}
```

#### Negroni
```go
package main

import ...

func main() {
	StartServer()
}

func StartServer() {
	r := mux.NewRouter()

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte("My Secret"), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
	})

	r.HandleFunc("/ping", PingHandler)
	r.Handle("/secured/ping", negroni.New(
		negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(SecuredPingHandler)),
	))
	http.Handle("/", r)
	http.ListenAndServe(":3001", nil)
}

type Response struct {
	Text string `json:"text"`
}

func respondJson(text string, w http.ResponseWriter) {
	response := Response{text}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func PingHandler(w http.ResponseWriter, r *http.Request) {
	respondJson("All good. You don't need to be authenticated to call this", w)
}

func SecuredPingHandler(w http.ResponseWriter, r *http.Request) {
	respondJson("All good. You only get this message if you're authenticated", w)
}
```

#### Martini
```go
package main

import ...

func main() {
	StartServer()
}

func StartServer() {
	m := martini.Classic()

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte("My Secret"), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
	})

	m.Get("/ping", PingHandler)
	m.Get("/secured/ping", jwtMiddleware.CheckJWT, SecuredPingHandler)

	m.Run()
}

type Response struct {
	Text string `json:"text"`
}

func respondJson(text string, w http.ResponseWriter) {
	response := Response{text}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func PingHandler(w http.ResponseWriter, r *http.Request) {
	respondJson("All good. You don't need to be authenticated to call this", w)
}

func SecuredPingHandler(w http.ResponseWriter, r *http.Request) {
	respondJson("All good. You only get this message if you're authenticated", w)
}
```

#### Gin
```go
package main

import ...

func main() {
	startServer()
}

var jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		return []byte("your auth0 client secret here"), nil
	},
	SigningMethod: jwt.SigningMethodHS256,
})

func checkJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwtMid := *jwtMiddleware
		if err := jwtMid.CheckJWT(c.Writer, c.Request); err != nil {
			c.AbortWithStatus(401)
		}
	}
}

func startServer() {
	r := gin.Default()

	r.GET("/ping", func(g *gin.Context) {
		g.JSON(200, gin.H{"text": "Hello from public"})
	})

	r.GET("/secured/ping", checkJWT(), func(g *gin.Context) {
		g.JSON(200, gin.H{"text": "Hello from private"})
	})

	r.Run(":3002")
}
```

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository's issue section. Please do not report security vulnerabilities on the public GitHub issue tracker.

## Original Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
