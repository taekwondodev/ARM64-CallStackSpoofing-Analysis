.PHONY: all clean

PDF = main.pdf
PDFLATEX = pdflatex -interaction=nonstopmode

all:
	$(PDFLATEX) main.tex
	bibtex main
	$(PDFLATEX) main.tex
	$(PDFLATEX) main.tex

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc *.fls *.fdb_latexmk *.run.xml $(PDF)
