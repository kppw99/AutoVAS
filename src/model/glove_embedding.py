'''
This file is for Glove Embedding.
If you have trouble to install glove_python library,
please execute this file on google CoLab.
'''

from google.colab import drive

drive.mount('/content/gdrive')

from glove import Corpus, Glove
from gensim.scripts.glove2word2vec import glove2word2vec
from gensim.models import KeyedVectors
from os.path import isfile
import numpy as np

path = '/content/gdrive/My Drive/Colab Notebooks/'

_CORPUS_FILE = path + 'sard_corpus.txt'
_GV_MODEL_TEMP_FILE = path + 'sard_gv.temp'
_GV_MODEL_FILE = path + 'sard_gv.model'

EMBEDDING_DIM = 300


def create_glove_model():
    print('[*] Create Glove model')
    if not isfile(_CORPUS_FILE):
        print('[!] Please check the corpus file: %s' % _CORPUS_FILE)
        return
    tokens = list()
    with open(_CORPUS_FILE) as f:
        lines = f.readlines()
        for line in lines:
            temp = line[:-1].split(' ')
            tokens.append(temp[:len(temp)])

    corpus = Corpus()
    corpus.fit(tokens, window=5)

    print('[-] Glove embedding ...')
    model = Glove(no_components=EMBEDDING_DIM)
    model.fit(corpus.matrix, epochs=200, no_threads=4, verbose=False)
    model.add_dictionary(corpus.dictionary)
    print('[-] save Glove model')
    with open(_GV_MODEL_TEMP_FILE, "w") as f:
        for word in model.dictionary:
            f.write(word)
            f.write(" ")
            for i in range(0, EMBEDDING_DIM):
                f.write(str(model.word_vectors[model.dictionary[word]][i]))
                f.write(" ")
            f.write("\n")
    glove2word2vec(glove_input_file=_GV_MODEL_TEMP_FILE, word2vec_output_file=_GV_MODEL_FILE)


def glove_test():
    result = [['this', 'is', 'an', 'apple']]
    corpus = Corpus()
    corpus.fit(result, window=5)

    glove = Glove(no_components=100, learning_rate=0.05)
    glove.fit(corpus.matrix, epochs=20, no_threads=4, verbose=True)
    glove.add_dictionary(corpus.dictionary)
    print(glove.dictionary)
    print(glove.word_vectors[3])

    with open(_GV_MODEL_FILE, "w") as f:
        for word in glove.dictionary:
            f.write(word)
            f.write(" ")
            for i in range(0, 100):
                f.write(str(glove.word_vectors[glove.dictionary[word]][i]))
                f.write(" ")
            f.write("\n")
    # glove.save(_GV_MODEL_FILE, binary=False)
    glove2word2vec(glove_input_file=_GV_MODEL_FILE, word2vec_output_file=_GV_W2V_MODEL_FILE)
    # with open(_GV_MODEL_FILE, 'rb') as f:
    #   buf  = f.read()
    #   print(buf)
    model = KeyedVectors.load_word2vec_format(_GV_W2V_MODEL_FILE, binary=False)
    print(model.word_vec('apple'))
    # model = loadGloveModel(_GV_W2V_MODEL_FILE)


if __name__ == '__main__':
    create_glove_model()
    # glove_test()

