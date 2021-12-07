# metamask-login
```php
$msg = "must sign:123";
$address = "0x95F64eCd5426e439c177846ac8Aadb1AC7aAE027";
$sign = '0x6171238faa84cb9b938900acce9ff487a8757da9a906ef89c800c2d38c6240d320b1abe3b087afac8be6ed09db2c8bf19ae9388fbcda8b35f93e766a8abd5f691b';

$signVerify = new \lexerom\SignVerify();
$result = $signVerify->verify($msg, $sign, $address);
```

See test.html for javascript example using web3.js
