from scapy.all import * 
import urllib2
import sys
import argparse

def analysisPcap(pcapfile):

	p = rdpcap(pcapfile)

	sessions = p.sessions()

	with open('dga.txt','r') as f:

		with open('result.txt','a+') as r:
		
			dgas = f.readlines()[18:]

			mylist = []
			for dga in dgas:

				mylist.append(dga.split('\t')[1])
			data = set(mylist)

			#print data[0]

					

			for session in sessions:
					
				for pa in sessions[session]:
							
					try:
						if pa[UDP].dport == 53:

							print pa.show()

							qname = (pa[DNS].qd.qname)
							qname = qname.decode('utf-8')[:-1]
							#print qname,dga
							if qname in data:

								for dga in dgas:

									if qname in dga:

										print 'Found dga'
										#print pa.show()
							 			r.write(pa[IP].src + '-------')
							 			r.write(dga +'\r\n' )						
								
							else:
								 		
								#print 'Not Found dga' +'||' + qname
								pass

					
					except:
									
							print 'Not DNS packet'
				
							
			r.close()
		f.close()

		print 'Analysis Complete'




def downloadDGA():
	print "downloading DGA file"
	url = 'http://data.netlab.360.com/feeds/dga/dga.txt' 
	f = urllib2.urlopen(url) 
	data = f.read() 
	with open("dga.txt", "wb") as code:

		code.write(data)
    	print "download complete"
    	code.close()

if __name__ == '__main__':

	parser = argparse.ArgumentParser(description="Find DGA in Pcapfile，result in the result.txt file")

	parser.add_argument("-f",  type = str, dest = "pcapfile",help = "pcap filename")

	args = parser.parse_args()

	pcapfile = args.pcapfile
	
	if pcapfile:

		downloadDGA()
		analysisPcap(pcapfile)
	else:
		print "Missing pcapfile, run 'python xxx.py -h'"
