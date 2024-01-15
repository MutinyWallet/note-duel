pack:
    wasm-pack build --dev --weak-refs --target web --scope benthecarman

link:
    wasm-pack build --dev --weak-refs --target web --scope benthecarman && cd pkg && pnpm link --global

login:
    wasm-pack login --scope=@benthecarman

check:
    cargo check
    cargo check --target wasm32-unknown-unknown

clippy:
    cargo clippy
    cargo clippy --target wasm32-unknown-unknown
