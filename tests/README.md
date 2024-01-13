# Language/stack tests

This directory contains subdirectories for language/stack specific tests to see whether we
can intercept their outgoing web requests. Most come with a Makefile as "executable documentation".

Note that a language/stack being represented here does not mean it works. Some of the subdirectories
are purely to show that things don't work, like golang.

## Overview

* [c-curl-openssl](c-curl-openssl): C with libCurl built against OpenSSL. Works.
* [golang-builtin](golang-builtin): Golang with built-in HTTP client. Does not work, Golang libraries are statically
  linked and we intercept DLLs.
* [nodejs-builtin](nodejs-builtin): NodeJS with built-in HTTP client. Works.
* [php-file-get-contents](php-file-get-contents): PHP with built-in HTTP via `file_get_contents()` call (most likely
  eventually hitting libcurl). Works.
* [python3-urllib3](python3-urllib3): Python3 using `requests` which in turn uses `urllib3`. Works.
* [ruby-builtin](ruby-builtin): Ruby with built-in `net/http` library. Works.
* [rust-hyper](rust-hyper): Rust using `reqwest` which in turn uses `hyper`. Works.
