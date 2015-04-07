SignedRequest (v.1.0.0)
=======================
[![Build Status](https://travis-ci.org/spiderrobb/SignedRequest.svg?branch=master)](https://travis-ci.org/spiderrobb/SignedRequest)

The SignedRequest class is an easy and feature rich way to encode and decode signed requests. Signed requests are used by companies such as Facebook, Kongregate, and Salesforce to pass data to 3rd party applications in a secure and reliable way.

*Note: SignedRequest does not Encrypt your data, it Encodes your data. All data inside a SignedRequest can be read by anyone. SignedRequest's are useful when you want to trust the data.*

##Format

A signed request is a concatenation of a HMAC SHA-256 (HMAC SHA-256 by default) signature string, a period (.), and a base64url encoded JSON object. It looks somthing like this (without the newlines).:
```
vlXgu64BQGFSQrY0ZcJBZASMvYvTHu9GQ0YM9rjPSso
.
eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsIjAiOiJwYXlsb2FkIn0
```
The Signed request consists of a signature and a payload `SIGNATURE.PAYLOAD`

##Basic Use

The most basic use of a signed request is to encode the data with a secret, and pass the data through HTTP POST or GET, then decode the signed request using the same secret. The Simplest use is:
```php
// File that is encoding Signed Request
// ------------------------------------
// defining secret to encode data with
$mySecret = '[My Super Secret String]';

// defining data to encode in signed request
// Note: myData does not need to be an array, it can be an Array, String, Boolean... etc.
$myData   = array(
    'dataKey' => 'dataValue'
);

$mySR     = SignedRequest::encode(
    $myData, array('secret' => $mySecret)
);


// File That is decoding Signed Request
// ------------------------------------
// defining secret to decode data with
$mySecret = '[My Super Secret String]';

// decoding signed request
try {
    // decoding signed request using same secret
    $myData = SignedRequest::decode(
        $mySR, array(
            'secret' => $mySecret
        )
    )
    print_r($myData);
} catch (Exception $e) {
    // signed request has been malformatted or cannot be trusted
    var_dump($e);
}

/* output
Array(
   'dataKey' => 'dataValue'
)
*/
```


##Features

###Support for multiple hash algorithms

Hash algorithms supported include all algorithms in php [hash_algos](http://php.net/manual/en/function.hash-algos.php)

**Example:**
```php
$mySecret = '[My super secret secret]';
$myData   = array(
    'dataKey' => 'dataValue'
);
$mySR     = SignedRequest::encode(
    $myData, array(
        'secret'    => $mySecret,
        'algorithm' => 'HMAC-SHA1' // (optional) default: HMAC-SHA256
    )
);
```

To get a list of supported algorithms you can use the function:
```php
$supportedAlgorithms = SignedRequest::getAlgorithms();
```

###Expiration Date

The ability to specify a specific date for the signed request to expire. (unix time stamp format)

**Example:**
```php
$mySecret = '[My super secret secret]';
$myData   = array(
    'dataKey' => 'dataValue'
);
$mySR     = SignedRequest::encode(
    $myData, array(
        'secret'  => $mySecret,
        'expires' => strtotime('2015-01-01 01:00:00')
    )
);
```

###Time to Expire

The ability to specify an amount of time (in seconds) until the signed requests expires.

**Example:**
```php
$mySecret = '[My super secret secret]';
$myData   = array(
    'dataKey' => 'dataValue'
);
$mySR     = SignedRequest::encode(
    $myData, array(
        'secret'  => $mySecret,
        'timeout' => 3600 // signed request will expire in 1 hour
    )
);
```

###Method Validation

Using best practice the same secret should not be used in multiple situations. Say you want to encode an id for an `object1`, so you encode data like this:
```php
$myData = array(
    'id' => 153
);
```
Now you want to encode an id for an `object2` so you encode it the same way:
```php
$myData = array(
    'id' => 351
);
```
If the same secret is used in both examples than it is possible for sombody to take a secret for `object1` and use it in a different context for `object2`.

To protect yourself from this security hazard you can use the method option.

**Example:**
```php
// Encoding data in signed request using method attribute
$mySecret = '[My super secret secret]';
$myData   = array(
    'dataKey' => 'dataValue'
);
$mySR     = SignedRequest::encode(
    $myData, array(
        'method'  => 'object1',
        'timeout' => 3600 // signed request will expire in 1 hour
    )
);

// Decoding data in signed request using method attribute
try {
    // decoding signed request using same secret
    $myData = SignedRequest::decode(
        $mySR, array(
            'method' => 'object1',
            'secret' => $mySecret
        )
    )
    print_r($myData);
} catch (Exception $e) {
    // signed request has been malformatted or cannot be trusted
    var_dump($e);
}
```