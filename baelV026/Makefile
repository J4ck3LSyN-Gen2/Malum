.PHONY: all clean

all: dist/bael

libbael_rust.so: src/lib.rs Cargo.toml
	cargo build --release
	cp target/release/libbael_rust.so .

dist/bael: bael.py libbael_rust.so
	pyinstaller --onefile --add-binary "libbael_rust.so:." bael.py

clean:
	rm -rf build dist target libbael_rust.so *.spec
