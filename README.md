# yaratest

YARA testing tools for reliable and fast rule development.

## Usage

### Adding Hashes


```
yaratest --add-hashes --positive <path>
```

### Watch Loop

(In Development)

yaratest supports a tight development iteration loop by watching for YARA rule updates and re-testing ...

Fast iterative development of rules based on a set of expected positive matches ande expected negative matches:

```
yaratest --watch --positive /malware --negative $PATH */.yar
```

yaratest will then watch for updates to the YARA files before rescanning, with an optional hit/miss cache.


