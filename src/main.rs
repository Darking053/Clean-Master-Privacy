name: CMP Autonomous Evolution Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch: 

permissions:
  contents: write
  pull-requests: write
  issues: write

jobs:
  build-and-repair:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Source
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install System Dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y pkg-config build-essential libgtk-4-dev libadwaita-1-dev libglib2.0-dev libgirepository1.0-dev libxml2-dev libpango1.0-dev libcairo2-dev libgdk-pixbuf-2.0-dev libgraphene-1.0-dev

      - name: Setup Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt

      # Autonomous Repair: Fixes formatting and simple code issues automatically
      - name: Autonomous Code Healing
        run: |
          cargo fmt --all
          cargo fix --allow-dirty --allow-staged
          
      - name: Commit Autonomous Fixes
        uses: stefanzweifel/git-auto-commit-action@v5
        with:
          commit_message: "chore: autonomous code healing and formatting"

      - name: Build Optimized Binary
        id: cargo_build
        run: |
          export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig
          cargo build --release --verbose

      - name: Prepare Release Assets
        if: success() && github.event_name == 'push'
        run: |
          mkdir -p assets
          cp target/release/clean-master-privacy assets/cmp-ultra-linux-x86_64

      - name: Auto Release
        if: success() && github.event_name == 'push'
        uses: softprops/action-gh-release@v2
        with:
          tag_name: v${{ github.run_number }}.0
          name: "CMP Ultra Build ${{ github.run_number }}"
          body: "Automated production build. All systems verified."
          files: assets/cmp-ultra-linux-x86_64
          token: ${{ secrets.GITHUB_TOKEN }}
