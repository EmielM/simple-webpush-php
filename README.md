# simple-webpush-php

Simple webpush+payload implementation in PHP without a gazillion dependencies.

- The elliptic curve multiplication operations are rolled-in instead of library-based, so don't use for very secret payloads.
- Payloads are not padded, so the provider might infer its payload content based on length.

### Dependencies
None but PHP5.6/PHP7.0 with the `gmp` module enabled.

### Usage

- Create server-side EC key combo with NIST-256 parameters:

  ```
  openssl ecparam -name prime256v1 -genkey > webpush.pem
  openssl ec -in webpush.pem -param_out -param_enc explicit -text
  ```

- Copy the `pub` and `priv` parts into `WebPush::$serverPub` and `WebPush::$serverPriv`.

- If you want to send to Chrome: request a GCM project key and fill in `WebPush::$gcmKey`.

- Send using `WebPush::send()`:

  ```php
  <?php
  include 'AESGCM.php'; 
  include 'WebPush.php';

  $sub = '{"endpoint":"https://android.googleapis.com/gcm/send/d6tafFvQKfg:APA91bHsT8vbDXWCUFYiEUW6wHsLIFD5qMxr8HB1yi71LfeXFR_3DVElEKzheMVZqY1RfDhTHPhqbaqxn6O8ASfDhakT487D2Yw_7uFgDHQeYfBjnIlx5XLigiTKRErheTJEw7F6q58b","keys":{"p256dh":"BDXLnAJ9eHeX1wBKk3DEmDmTYP_0XRsg7VdXlVFGrpJAR0varADp6LgUE3egRMzvqK0LCH13I0I25LeOg3t7k08=","auth":"3ND-J-JrZRhM1qHeKb_WaQ=="}}';

  $noti = ['title' => 'title', 'text' => 'text']; // configure your service worker to parse this payload

  $ok = WebPush::send(json_decode($sub, true), json_encode($noti));
  ```

### Feedback

- Bugs on the GitHub issue tracker.
- Let me know if you're using this for cool projects.

### Licence
MIT licensed

