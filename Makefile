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

install:
	@install -d $(prefix)/include $(prefix)/lib
	@install $(INCDIR)$(NAME).h $(prefix)/include
	@install $(LIBDIR)lib$(NAME).so $(prefix)/lib

uninstall:
	@rm -f $(prefix)/include/$(NAME).h $(prefix)/lib/lib$(NAME).so

debug:
	@cargo build --features "cbindings"

test:
	@cargo test --features "cbindings"
	@make -C tests clean test
	@echo
	@echo "All tests completed successfully."

tests: test

clean:
	@cargo clean
	@make -C tests clean

doc:
	@rm -rf $(DOC_PATH)
	@cargo doc --no-deps --features "cbindings"

release: test
	@git diff --exit-code >/dev/null || (echo "The local git directory is not clean." && exit 1)
	@git diff --exit-code --cached >/dev/null || (echo "The local git directory is not clean." && exit 1)
	@test "$(shell git tag -l $(TAG_NAME))" = "" || (echo "Version $(VERSION) already exists." && exit 1)
	@git tag -s $(TAG_NAME) -m "$(NAME) $(VERSION)"
	@git push origin $(TAG_NAME)
	@cargo package
	@cargo publish
	@make sync_doc
	@echo "$(NAME) $(VERSION) released."

sync_doc: test doc
	@rsync -havz --progress $(DOC_PATH) "what.tf:/srv/http/what.tf/"
	@echo "Documentation updated."

help:
	@echo "Default target: $(NAME)"
	@echo
	@echo "Available targets:"
	@echo "   $(NAME)            create a release build"
	@echo "   install         install $(NAME)"
	@echo "   uninstall       uninstall $(NAME)"
	@echo "   debug           create a debug build"
	@echo "   test            run the tests"
	@echo "   tests           alias for 'test'"
	@echo "   clean           remove compiled files"
	@echo "   doc             generate the local documentation"
	@echo "   help            print this message"
	@echo
	@echo "Options:"
	@echo "   prefix=<path>   set the installation prefix (default: /usr)"
