PREFIX     = /usr
INCLUDEDIR = $(PREFIX)/include
LIBDIR     = $(PREFIX)/lib
LA_INCDIR  = ./include
LA_LIBDIR  = ./target/release
DOC_PATH   = ./target/doc
CARGO_CNF  = Cargo.toml
NAME       = $(shell grep name $(CARGO_CNF) | head -n1 | cut -d '"' -f2)
VERSION    = $(shell grep version $(CARGO_CNF) | head -n1 | cut -d '"' -f2)
TAG_NAME   = v$(VERSION)


all: $(NAME)

$(NAME):
	@cargo build --release --all-features

audit:
	@cargo outdated
	@cargo audit

install:
	@install -D --mode=0644 $(LA_INCDIR)/$(NAME).h $(DESTDIR)$(INCLUDEDIR)/$(NAME).h
	@install -D --mode=0755 $(LA_LIBDIR)/lib$(NAME).a $(DESTDIR)$(LIBDIR)/lib$(NAME).a
	@install -D --mode=0755 $(LA_LIBDIR)/lib$(NAME).so $(DESTDIR)$(LIBDIR)/lib$(NAME).so

debug:
	@cargo build --all-features

test: debug
	@cargo test --all-features
	@make -C tests clean test
	@echo
	@echo "All tests completed successfully."

tests: test

test_nightly:
	@rustup run nightly cargo test --all-features
	@make -C tests clean test
	@echo
	@echo "All tests completed successfully."

clean:
	@cargo clean
	@make -C tests clean

doc:
	@rm -rf $(DOC_PATH)
	@cargo doc --no-deps --all-features

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

.PHONY: $(NAME) all audit install debug test tests test_nightly clean doc release help
