clean:
	rm -r webcrawler-output

install:
	sudo apt-get install libsll-dev

teste:
	python webcrawler.py 2 https://ccl.northwestern.edu/netlogo/

auto:
	python webcrawler.py 2 https://cobalto.ufpel.edu.br
