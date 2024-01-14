dev:
	docker-compose up -d

dev-down:
	docker-compose down

new-migrate:
	sqlx migrate add -r $(name)

migrate-up:
	sqlx migrate run

migrate-down:
	sqlx migrate revert

server:
	cargo watch -q -c -w src/ -x run

dep:
	cargo add actix-web
	cargo add actix-cors
	cargo add serde_json
	cargo add serde --features derive
	cargo add chrono --features serde
	cargo add env_logger
	cargo add dotenv
	cargo add uuid --features "serde v4"
	cargo add sqlx --features "runtime-async-std-native-tls postgres chrono uuid"
	cargo add jsonwebtoken
	cargo add argon2
	cargo add base64
	cargo add futures
	cargo add rand_core --features "std"
	cargo add redis --features "tokio-comp"
