DOC_PATH   = target/doc/
CARGO_CNF  = Cargo.toml
NAME       = $(shell cat $(CARGO_CNF) | grep name | head -n1 | cut -d '"' -f2)
VERSION    = $(shell cat $(CARGO_CNF) | grep version | head -n1 | cut -d '"' -f2)
TAG_NAME   = v$(VERSION)
LIBDIR     = ./target/release/
INCDIR     = ./include/
prefix    ?= /usr


all: $(NAME)

$(NAME):
	@cargo build --release --features "cbindings"

audit:
	@cargo outdated
	@cargo audit

install:
	@install -d $(prefix)/include $(prefix)/lib
	@install --mode=0644 $(INCDIR)$(NAME).h $(prefix)/include
	@install --mode=0755 $(LIBDIR)lib$(NAME).so $(prefix)/lib

uninstall:
	@rm -f $(prefix)/include/$(NAME).h $(prefix)/lib/lib$(NAME).so

debug:
	@cargo build --features "cbindings"

test: debug
	@cargo test --features "cbindings"
	@make -C tests clean test
	@echo
	@echo "All tests completed successfully."

tests: test

test_nightly:
	@rustup run nightly cargo test --features "cbindings"
	@make -C tests clean test
	@echo
	@echo "All tests completed successfully."

clean:
	@cargo clean
	@make -C tests clean

doc:
	@rm -rf $(DOC_PATH)
	@cargo doc --no-deps --features "cbindings"

release: test audit
	@git diff --exit-code >/dev/null || (echo "The local git directory is not clean." && exit 1)
	@git diff --exit-code --cached >/dev/null || (echo "The local git directory is not clean." && exit 1)
	@test "$(shell git tag -l $(TAG_NAME))" = "" || (echo "Version $(VERSION) already exists." && exit 1)
	@git tag -s $(TAG_NAME) -m "$(NAME) $(VERSION)"
	@git push origin $(TAG_NAME)
	@cargo package
	@cargo publish
	@echo "$(NAME) $(VERSION) released."

help:
	@echo "Default target: $(NAME)"
	@echo
	@echo "Available targets:"
	@echo "   $(NAME)       create a release build"
	@echo "   audit           audit dependencies"
	@echo "   install         install $(NAME)"
	@echo "   uninstall       uninstall $(NAME)"
	@echo "   debug           create a debug build"
	@echo "   test            run the tests"
	@echo "   tests           alias for 'test'"
	@echo "   test_nightly    run the tests against rust nightly"
	@echo "   clean           remove compiled files"
	@echo "   doc             generate the local documentation"
	@echo "   help            print this message"
	@echo
	@echo "Options:"
	@echo "   prefix=<path>   set the installation prefix (default: /usr)"

.PHONY: all audit install uninstall debug test tests test_nightly clean doc release help
