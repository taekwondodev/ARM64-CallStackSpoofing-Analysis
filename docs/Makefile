.PHONY: all clean

PDF = main.pdf

all: $(PDF)

$(PDF): main.tex chapters/*.tex biblio.bib
	latexmk -pdf -bibtex -interaction=nonstopmode main.tex

clean:
	latexmk -C
	rm -f *.bbl *.run.xml
