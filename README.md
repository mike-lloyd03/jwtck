# JSON Web Token Check

Simple CLI tool to parse a JWT and print it's contents to the terminal.


## Usage

This tools reads from stdin and prints out colorized json output.

```bash
cat file.jwt | jwtck
```

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "iat": 1516239022,
    "name": "John Doe",
    "sub": "1234567890"
  }
}
```
