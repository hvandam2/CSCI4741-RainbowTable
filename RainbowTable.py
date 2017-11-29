# Cyber Security - CSCI 4741
# Group Project - Rainbow Tables
#
# Author:
#	William Rooney
#
# Team Members:
#	William Rooney
#	Howard Van Dam
#	Jonathan Trejo

import hashlib, re, os, math, timeit
from itertools import product
from string import ascii_lowercase, digits

class RainbowTable:
	def __init__(self, k=100, strLength=4, generate=True):

		"""
		RainbowTable Class: builds a rainbow table with k
		reduction functions. Each chain's starting
		plaintext consists of strLength characters of the set [0-9].
		"""
		self.k = k
		self.strLength = strLength
		self.table = {}

		# Create a set of all possible password of length strLength
		if generate: self.passwordSet = [''.join(p) for p in product(digits, repeat=self.strLength)]

	def load(self, fileName):
		"""
		Load a pre-computed rainbow table.
		The first line contains the k value
		an entry contains start and end values that are comma delimited
		each entry in the table is newline delimited
		"""
		try:
			infile = open(fileName, 'r')
			self.k = int(next(infile))
			self.table = {} # reset table if already populated
			for line in infile:
				try:
					line = line.strip('\n')
					data = line.split(',')
					self.table[data[0]] = data[1]
				except IndexError:
					print 'Error: Invalid file contents in file:',fileName
					return
			infile.close()
		except IOError:
			print 'Error: Could not read file:',fileName

	def save(self, fileName=None):
		"""
		Save the current rainbow table.
		The first line contains the k value
		an entry contains start and end values that are comma delimited
		each entry in the table is newline delimited
		"""
		if fileName == None:
			fileName = 'rainbowTable_len' + str(self.strLength) + '_k' + str(self.k) + '.txt'
		try:
			outfile = open(fileName, 'w')
			outfile.write('%s\n' % str(self.k))
			for start, end in self.table.items():
				outfile.write('%s,%s\n' % (start, end))
			outfile.close()
		except IOError:
			print 'Error: Could not write to file:',fileName


	def generate(self):
		""" Generate a Rainbow Table with the character set [0-9] used for plaintext inputs with k reduction functions used in a chain"""

		for plaintext_Start in self.passwordSet:	
			# Generate Chain
			plaintext_End = plaintext_Start
			for i in range(self.k):
				hash_object = hashlib.md5(plaintext_End.encode())	# Create hash
				plaintext_End = self.R(i, hash_object.hexdigest())	# Reduce to numeric plaintext
			if plaintext_End not in self.table.values():
				self.table[plaintext_Start] = plaintext_End			# If final plaintext in chain has not already been created then add the starting plaintext and ending plaintext to the table

	def R(self, i, hash_object): # Play with this function to find better rainbow table generations
		""" Reduction function #i for i = 0,1,2,...,k-1 : Return a plaintext string of length strLength that contains characters [0-9] """
		return str(int(''.join(re.findall("[0-9]+",hash_object))) + i)[-self.strLength:]	# Extract all digits from hash string and add i, return last strLength characters


	def crack(self,passHash):
		""" Attempt to crack given hash to find a matching password """
		newHash = passHash
		iteration = 1
		passPlaintext = ''
		for iteration in range(self.k):
			for i in range(iteration+1): # Apply R(k-iteration) through R(k) reduction functions on hash
				passPlaintext = self.R(i+(self.k-1-iteration), newHash)
				newHash = hashlib.md5(passPlaintext.encode()).hexdigest()
			if passPlaintext in self.table.values(): # Found match in rainbow table, rebuild chain from starting entry in table
				newPlaintext = next((key for key, val in self.table.items() if val == passPlaintext), None)
				if newPlaintext is not None:
					for j in range(self.k):
						newHash = hashlib.md5(newPlaintext.encode()).hexdigest()
						if newHash == passHash:
							self.password = newPlaintext
							return True # Found the matching password
						newPlaintext = self.R(j, newHash)
		return False # Failed to find a match

	def getExampleChain(self, plaintext='1234', k=5):
		"""
		Creates a chain and returns a string of the entire chain with the following format (t=plaintext, h=hash, Rk=reduction function k):
			    t --> h --> R1
			--> t --> h --> R2
			--> t --> h --> R3
			--> ...
			--> t --> h --> Rk --> t
		To be used in jupyter when displaying how chains are constructed.
		"""
		self.strLength = len(plaintext)
		transition = ' --> '
		chain = ' '*len(transition) + plaintext + transition
		for i in range(k):
			hash_object = hashlib.md5(plaintext.encode())	# Create hash
			plaintext = self.R(i, hash_object.hexdigest())	# Reduce to numeric plaintext

			# format output
			chain += hash_object.hexdigest() + transition + 'R' + str(i+1)
			if i != k-1:
				chain += '\n' + transition + plaintext + transition
			else:
				chain += transition + plaintext
		return chain


"""
----------------------------------------------------------------------------------------------
  TESTS
----------------------------------------------------------------------------------------------
"""

def crackPassExample():
	passPlainText = '01234'
	passHash = hashlib.md5(passPlainText.encode()).hexdigest()
	#passHash = '81dc9bdb52d04dc20036dbd8313ed055'

	if os.name == 'nt': os.system('cls')
	else: os.system('clear')

	# Try two 3 character rainbow tables
	rainbowTable1 = RainbowTable(31,3,False) # use RainbowTable(31,3,True) & rainbowTable1.generate() to generate the same rainbow table with k=31 and strLength = 3
	rainbowTable2 = RainbowTable(30,3,False)
	rainbowTable1.load('rainbowTable_len3_k31.txt')
	print 'Attempting to crack 3 character password with hash:',passHash
	if rainbowTable1.crack(passHash):
		print 'Found password:',rainbowTable1.password,'\n'
		return
	else:
		print 'Attack failed: trying new table'
		rainbowTable2.load('rainbowTable_len3_k30.txt')
		if rainbowTable2.crack(passHash):
			print 'Found password:',rainbowTable2.password,'\n'
			return
		else:
			print 'Three character password attack failed\n'

	# Try two 4 character rainbow tables
	rainbowTable3 = RainbowTable(100,4,False)
	rainbowTable4 = RainbowTable(99,4,False)
	rainbowTable3.load('rainbowTable_len4_k100.txt')
	print 'Attempting to crack 4 character password with hash:',passHash
	if rainbowTable3.crack(passHash):
		print 'Found password:',rainbowTable3.password,'\n'
		return
	else:
		print 'Attack failed: trying new table'
		rainbowTable4.load('rainbowTable_len4_k99.txt')
		if rainbowTable4.crack(passHash):
			print 'Found password:',rainbowTable4.password,'\n'
			return
		else:
			print 'Four character password attack failed\n'

	# Try two 5 character rainbow tables
	rainbowTable5 = RainbowTable(316,5,False)
	#rainbowTable6 = RainbowTable(99,4,False)
	rainbowTable5.load('rainbowTable_len5_k316.txt')
	print 'Attempting to crack 5 character password with hash:',passHash
	if rainbowTable5.crack(passHash):
		print 'Found password:',rainbowTable5.password,'\n'
		return
	else:
		print 'Attack failed'

"""
# Run example and calculate exeuction time
start = timeit.default_timer()
crackPassExample()
stop = timeit.default_timer()
print 'Execution time:',format(stop-start,'3.3f'),'seconds\n'

# Create an example chain
rainbowTable = RainbowTable(k=5,strLength=4,generate=False)
print 'Example chain:\n'
print rainbowTable.getExampleChain(plaintext='1234', k=5)
"""
