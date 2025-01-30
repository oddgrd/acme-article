### Running locally

1. We'll need a [Pebble](https://github.com/letsencrypt/pebble) server started, this will serve as
our ACME server. You can install this locally, following their
[official instructions](https://github.com/letsencrypt/pebble?tab=readme-ov-file#install), or you
can start it in Docker, which we'll do.
2. We have a bare-bones docker-compose.yml file in this repo. It is set to connect to our ACME
challenge server that is running locally, with the the domain we try to provision a certificate for
being mapped to the host machine network.
3. Copy the `pebble.minica.pem` certificate from the [Pebble repository](https://github.com/letsencrypt/pebble/tree/main/test/certs), and place it in the root of this repository.
See the README there for why we need that cert.
3. Start Pebble with `docker compose up`.
4. Start your ACME client and challenge server: `cargo run`.
