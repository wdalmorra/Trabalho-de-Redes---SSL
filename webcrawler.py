import socket
import time
import re
import urlparse
import sys
import os
from threading import *

# FLAGS PARA DEBUG

# SEM ESCRITA
# Quando ela eh True, nenhum arquivo ou diretorio eh criado.
# Adicionalmente, mensagens de erro mais completas sao mostradas.
DEBUG_FLAG = False

# IMPRIME CABECALHO
# Quando ela eh True, o cabecalho obtido como resposta eh mostrado abaixo do
# endereco do site
IMPRIME_CABECALHO = False

NTHREADS = 8
BLOCO = 2048

def SinalizaErro():
# Apenas por economia
	if DEBUG_FLAG:		# DEBUG
		erro = sys.exc_info()[:2]
		ret = str(erro)

	else:
		ret = '\t<erro>\n'

	return ret


def GeraLink(scheme, host, path, s):
	ret = s

	if (re.match(r'mailto:|javascript:|JavaScript:', s)):
		ret = ""

	else:
		if re.match(r'//', s):
			ret = scheme + ":" + s
		elif re.match(r'/', s):
			ret = scheme + "://" + host + s

		elif not(re.match(r'https?://', s)):
			ret = scheme + "://" + path + '/' + s

	return ret


def CriaDiretorios(host, path, criar):
	# Diretorio correspondente ao host
	caminho = host
	lock.acquire()

	if not (caminho in diretorios):
		if criar:
			diretorios.append(caminho)
		lock.release()

		if criar and (not DEBUG_FLAG):		# DEBUG
			os.system("mkdir webcrawler-output/" + caminho + ' 2>> /dev/null')

	else:
		lock.release()

	# Diretorios correspondentes ao path
	novalista = re.split(r'/', path)
	novalista.pop()			# o ultimo elemento eh um nome de arquivo e nao de pasta

	if novalista:
		novalista.pop(0)	# o primeiro elemento eh uma string nula

	npastas = len(novalista)

	i = 0
	while i < npastas:
		caminho = caminho + '/' + novalista[i]
		lock.acquire()

		if not (caminho in diretorios):
			if criar:
				diretorios.append(caminho)
			lock.release()

			if criar and (not DEBUG_FLAG):		# DEBUG
				os.system("mkdir webcrawler-output/" + caminho + ' 2>> /dev/null')

		else:
			lock.release()

		i = i + 1

	return caminho



def Busca(url, prof_atual):

	global lista_por_visitar

	houve_erro = False

	parse = urlparse.urlparse(url)
	host = parse.netloc
	path = parse.path
	
	try:
		if parse.port == None:
			port = 80
		else:
			port = parse.port

	except:
		port = 80
	
	addr = host + path

	lock.acquire()
	if not (addr in lista_visitados):

		lista_visitados.append(addr)
		lock.release()

		scheme = parse.scheme
		msg = scheme + '://' + host + path + ', ' + str(prof_atual) + '\n'

		if not path:
			path = '/'

		# Inicia a comunicacao, envia a requisicao e recebe o cabecalho
		# mais o inicio do conteudo, se houver
		try:
			s = socket.create_connection((host, port), 10)
			s.send("GET " + path + " HTTP/1.1\r\nHost: "+ host + "\r\n\r\n")
			strg = s.recv(BLOCO)
		
		except socket.error:
			msg += SinalizaErro()
			houve_erro = True

		if not houve_erro:

			bytes_recebidos = len(strg)

			# Separa o cabecalho do inicio do conteudo
			resposta = re.match(r'(.*?)\n\r\n(.*)', strg, re.DOTALL)
			if resposta:
				cabecalho = resposta.group(1)
				conteudo = resposta.group(2)

				if IMPRIME_CABECALHO:
					print '\n' + cabecalho + '\n\n'
			
				# Define se a requisicao foi bem sucedida
				codigo_retorno = int(cabecalho.split(" ", 2)[1])

				# Verifica se o cabecalho disponibiliza o tamanho do
				# conteudo
				match = re.search(r'Content-Length: (\d+)', cabecalho)

				if match:
					tamanho_disponivel = True
					tam = int(match.group(1))

				else:
					tamanho_disponivel = False
			
			
				if codigo_retorno == 200 or codigo_retorno == 300:
				# Site encontrado

					# Assegura que os diretorios necessarios
					# existem
					caminho = CriaDiretorios(host,path,True)
				
					# Monta o caminho do arquivo de saida
					re_arquivo = re.search(r'/([^/]+)$', path)

					if re_arquivo:
						arq = re_arquivo.group(1)

					else:
						arq = 'index.html'
				
					nome = 'webcrawler-output/' + caminho + '/' + arq

				
					if not DEBUG_FLAG:		# DEBUG
						saida = open(nome, 'w')
				
					if not DEBUG_FLAG:		# DEBUG
						saida.write(conteudo)

					# Recebe o restante do conteudo
					# Se houver indicacao explicita de content-length,
					# ela deve ser respeitada. Senao, paramos quando o
					# server para de mandar.
					if tamanho_disponivel:
						bytes_recebidos = len(conteudo)

						while (bytes_recebidos < tam):

							try:
								strg = s.recv(BLOCO)
								# print len(strg)
								ultimo_br = bytes_recebidos
								bytes_recebidos += len(strg)
								conteudo = conteudo + strg

								if not DEBUG_FLAG:		# DEBUG
									saida.write(strg)

								if bytes_recebidos == ultimo_br:
									break

							except:
								msg += SinalizaErro()
								houve_erro = True
								break

					else:
						tentativas = 5

						while(tentativas > 0):

							try:
								strg = s.recv(BLOCO)
								bytes_recebidos = (len(strg))
								conteudo = conteudo + strg

								if not DEBUG_FLAG:		# DEBUG
									saida.write(strg)

							except:
								msg += SinalizaErro()
								houve_erro = True
								break

							if bytes_recebidos == 0:
								tentativas -= 1

							else:
								tentativas = 5

					# print conteudo

					if not DEBUG_FLAG:		# DEBUG
						saida.close()

					# Procura todos os links dentro de tags
					# <a href> na pagina recebida
					strg = conteudo
					strg = re.sub(r'<!--[\w\W]*?-->',r'',strg)
					matchies = re.findall(r'<a [\w\W]*?href=\"([^\"]+)\"',strg)

					visitar = []

					for match in matchies:
						link = GeraLink(parse.scheme, host, caminho, match)
						if link:
							visitar.append(link)

					lock.acquire()
					lista_por_visitar += visitar
					lock.release()
				
					if not houve_erro:
						msg += "\t<recebido>\n"
				
					print msg
			
				elif codigo_retorno == 301 or codigo_retorno == 302 or codigo_retorno == 307:
				# Fui redirecionado!

					caminho = CriaDiretorios(host,path,False)
				
					re_novo_endereco = re.search(r'Location: (.+)\r', cabecalho)

					if re_novo_endereco:
						novo_endereco = re_novo_endereco.group(1)

						novo_endereco = GeraLink(parse.scheme, host, caminho, novo_endereco)

						msg += '\t<redirecionado para ' + str(novo_endereco) + '>\n'
						print msg

						Busca(novo_endereco, prof_atual)

					else:
						msg += '\t<redirecionado sem endereco destino>\n'
						print msg
			
				else:
					msg += '\t<resposta com codigo invalido>\n'
					print msg
						
				s.close()
	else:
		lock.release()

def robots(url):
	resposta = ''
	msg = ''

	houve_erro = False

	parse = urlparse.urlparse(url)

	if not (parse.netloc in robots_visitados):
		robots_visitados.append(parse.netloc)

		try:
			if parse.port == None:
				port = 80
			else:
				port = parse.port

		except:
			port = 80

		msg = parse.netloc + '/robots.txt' + '\n'

		try:
			s = socket.create_connection((parse.netloc, port), 10)
			s.send("GET /" + "/robots.txt" + " HTTP/1.1\r\nHost: "+ parse.netloc + "\r\n\r\n")
			result = s.recv(BLOCO)

		except socket.error:
			SinalizaErro()
			houve_erro = True

		if houve_erro:
			return

		resposta = re.match(r'(.*?)\n\r\n(.*)', result, re.DOTALL)
		cabecalho = resposta.group(1)
		conteudo = resposta.group(2)

		codigo_retorno = int(cabecalho.split(' ', 2)[1])

		if codigo_retorno != 200:
			return

		re_tamanho = re.search(r'Content-Length: (.*)', cabecalho)
		if re_tamanho:
			tam = int(re_tamanho.group(1))

		if re_tamanho:
			while len(conteudo) < tam:
				try:
					result = s.recv(BLOCO)
					conteudo += result
				except:
					SinalizaErro()
					houve_erro = True
					break
		else:
			tentativas = 5
			while(tentativas > 0):
				try:
					result = s.recv(BLOCO)
					conteudo += result
					bytes_recebidos = len(result)
				except:
					SinalizaErro()
					houve_erro = True
					break
				if bytes_recebidos == 0:
					tentativas -= 1
				else:
					tentativas = 5

		if houve_erro:
			return

		matchies = re.findall(r'[Dd]isallow: (.*)', conteudo)
		for match in matchies:
			link = parse.netloc + match
			if not (link in lista_visitados):
				lista_visitados.append(link)
				msg += 'robots.txt: ' + link + '\n'

		print msg

def procura():

	global nsites
	global prof_atual

	while True:

		lock.acquire()

		nsites_local = nsites
		if nsites_local > 0:
			url = lista_por_visitar.pop(0)
			parse = urlparse.urlparse(url)
			if not (parse.netloc in robots_visitados):
				robots(url)
			nsites -= 1

		lock.release()

		if nsites_local > 0:
			Busca(url, prof_atual)
		else:
			break


def main(argc, argv):

	global nsites
	global prof_atual

	if argc != 3:
		print "Numero de parametros incorreto"
		print "Uso: python webcrawler.py <profundidade> <url>\n"
		sys.exit()

	try:
		profundidade = int(argv[1])
	except ValueError:
		print "Profundidade deve ser um inteiro!"
		print "Uso: python webcrawler.py <profundidade> <url>\n"
		sys.exit()

	URL_inicial = argv[2]

	#Cria o diretorio que vai conter todos as outras pastas dos hrefs
	os.system("mkdir webcrawler-output" + ' 2>> /dev/null')


	if not(re.match(r'https?://', URL_inicial)):
		URL_inicial = "http://" + URL_inicial

	lista_por_visitar.append(URL_inicial)

	while prof_atual <= profundidade:								# Profundidade
		threads = []
		nsites = len(lista_por_visitar)

		if nsites < NTHREADS:
			nthreads = nsites
		else:
			nthreads = NTHREADS

		k = 0
		while k < nthreads:
			t = Thread (target=procura)
			threads.append(t)
			t.start()
			k += 1

		k = 0
		while k < nthreads:
			t = threads.pop()
			t.join()
			k += 1

		prof_atual += 1


robots_visitados = []
lista_visitados = []
diretorios = []
lista_por_visitar = []
lock = Lock()
nsites = 0
prof_atual = 0

if __name__ == '__main__': main(len(sys.argv), sys.argv)
