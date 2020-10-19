import os
import datetime
import numpy as np
import pandas as pd
from os.path import isfile, isdir
import matplotlib.pyplot as plt

from tensorflow.keras import regularizers

from keras.models import Sequential
from keras.utils import to_categorical
from keras.callbacks import EarlyStopping
from sklearn.model_selection import KFold
from keras.preprocessing.text import Tokenizer
from keras.optimizers import Adam, Adamax, Nadam
from keras.preprocessing.sequence import pad_sequences
from keras.layers.normalization import BatchNormalization
from keras.layers import Dense, LSTM, GRU, Embedding, Dropout, Activation, Bidirectional

from imblearn.combine import SMOTEENN

from tqdm import tqdm
from pprint import pprint
from gensim.models import Word2Vec, FastText, KeyedVectors
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from sklearn.metrics import classification_report

FILEPATH = '../../dataset/token/'
_SNIPPET_FILES = [
    FILEPATH + 'sard_result_0001_1000.txt',
    FILEPATH + 'sard_result_1001_2000.txt',
    FILEPATH + 'sard_result_2001_3000.txt',
    FILEPATH + 'sard_result_3001_4000.txt',
    FILEPATH + 'sard_result_4001_5000.txt',
    FILEPATH + 'sard_result_5001_6000.txt',
    FILEPATH + 'sard_result_6001_7000.txt',
    FILEPATH + 'sard_result_7001_8000.txt',
    FILEPATH + 'sard_result_8001_9283.txt',
    # './SARD/result.txt'
    FILEPATH + 'nvd_result.txt'
]
_DATASET_FILE = 'sard_dataset.txt'
_CORPUS_FILE = 'sard_corpus.txt'
_W2V_MODEL_FILE = 'sard_w2v.model'
_D2V_MODEL_FILE = 'sard_d2v.model'
_S2V_MODEL_FILE = 'sard_s2v.model'
_FT_MODEL_FILE = 'sard_ft.model'
_GV_MODEL_FILE = 'sard_gv.model'

# for Embedding
CLASS_NUM = 2
MAX_WORDS = 200000
EMBEDDING_MODEL = 'w2v'
EMBEDDING_DIM = 300
SNIPPET_SIZE = 80

# for LSTM, GRU Model
TEST_SPLIT = 0.3
VALID_SPLIT = 0.2
K_FOLD = 5
BATCH_SIZE = 256
STATEFUL = True
HIDDEN_DIM = EMBEDDING_DIM
EPOCH_SIZE = 200

# for Regularization
EARLYSTOP = True
L1_REG = 0.001
L2_REG = 0.001
DROPOUT_RATE = 0.15 + np.random.rand() * 0.5

embedding_matrix = np.zeros((0, 0))

def _create_data():
    print('[#] Create data file')
    with open(_DATASET_FILE, 'w') as wf:
        print('[-] Write dataset file:', _DATASET_FILE)
        wf.writelines("label\tsnippet\n")
        for snippet_file in tqdm(_SNIPPET_FILES):
            with open(snippet_file, 'r') as rf:
                lines = rf.readlines()
                for snippet in lines:
                    snippet = snippet[:-1].split('#')
                    t_len = len(snippet) - 1
                    label = snippet[0]
                    tokens = snippet[3:t_len]
                    wf.writelines(label + '\t' + ' '.join(tokens) + '\n')
    with open(_CORPUS_FILE, 'w') as wf:
        print('[-] Write corpus file:', _CORPUS_FILE)
        for snippet_file in tqdm(_SNIPPET_FILES):
            with open(snippet_file, 'r') as rf:
                lines = rf.readlines()
                for snippet in lines:
                    snippet = snippet[:-1].split('#')
                    t_len = len(snippet) - 1
                    tokens = snippet[3:t_len]
                    wf.write(' '.join(tokens) + '\n')

def _split_data(X, y, test_split, split_shuffle=True):
    print('[#] Split data (%.2f : %.2f)' % (1.0-test_split, test_split))
    if split_shuffle:
        ind = np.arange(len(X))
        np.random.shuffle(ind)
        X = X[ind]
        y = y[ind]
    tr_size = int(len(X) * (1.0 - test_split))
    tr_X = X[:tr_size]
    te_X = X[tr_size:]
    tr_y = y[:tr_size]
    te_y = y[tr_size:]
    if STATEFUL:
        tr_size = int(int(int(tr_size * (1.0 - VALID_SPLIT)) / BATCH_SIZE) * BATCH_SIZE)
        tr_size += int(int(int(tr_size * VALID_SPLIT) / BATCH_SIZE) * BATCH_SIZE)
        # tr_size = int(int(tr_size / BATCH_SIZE) * BATCH_SIZE)
        te_size = int(int(len(te_X) / BATCH_SIZE) * BATCH_SIZE)
        tr_X = tr_X[:tr_size]
        te_X = te_X[:te_size]
        tr_y = tr_y[:tr_size]
        te_y = te_y[:te_size]
    print('[-] train data shape (X, y):', tr_X.shape, tr_y.shape)
    print('[-] test data shape (X, y):', te_X.shape, te_y.shape)
    return tr_X, tr_y, te_X, te_y

def _split_data_for_kfold(X, y, k_fold, split_shuffle=True):
    kf = KFold(n_splits=k_fold, shuffle=split_shuffle)
    if STATEFUL:
        kf_size = int(int(int(len(X)/BATCH_SIZE)/k_fold) * BATCH_SIZE) * k_fold
        print(kf_size)
        X = X[:kf_size]
        y = y[:kf_size]
    print('[-] data shape (X, y):', X.shape, y.shape)
    return X, y, kf

def _create_ft_model():
    print('[*] Create FastTest model')
    if not isfile(_CORPUS_FILE):
        print('[!] Please check the corpus file: %s' % _CORPUS_FILE)
        return
    corpus = list()
    with open(_CORPUS_FILE) as f:
        lines = f.readlines()
        for line in lines:
            temp = line[:-1].split(' ')
            corpus.append(temp[:len(temp)])
    print('[-] fasttext embedding ...')
    model = FastText(sentences=corpus, window=5, min_count=5, workers=4,
                     size=EMBEDDING_DIM, iter=200, sample=1e-4, sg=1, negative=5)
    print('[-] save fasttext model')
    model.save(_FT_MODEL_FILE)

def _create_w2v_model():
    print('[#] Create word2vec model')
    if not isfile(_CORPUS_FILE):
        print('[!] Please check the corpus file: %s' % _CORPUS_FILE)
        return
    corpus = list()
    with open(_CORPUS_FILE) as f:
        lines = f.readlines()
        for line in lines:
            temp = line[:-1].split(' ')
            corpus.append(temp[:len(temp)])
    print('[-] word2vec embedding ...')
    model = Word2Vec(sentences=corpus, window=5, min_count=5, workers=4,
                     size=EMBEDDING_DIM, iter=200, sample=1e-4, sg=1, negative=5)
    print('[-] save word2vec model')
    model.wv.save_word2vec_format(_W2V_MODEL_FILE)

def _create_d2v_model():
    print('[#] Create doc2vec model')
    if not isfile(_CORPUS_FILE):
        print('[!] Please check the corpus file: %s' % _CORPUS_FILE)
        return
    corpus = list()
    with open(_CORPUS_FILE) as f:
        lines = f.readlines()
        for idx, line in enumerate(lines):
            temp = line.split('\n')[0].strip()
            corpus.append(TaggedDocument(temp.split(' '), [idx]))
    print('[-] doc2vec embedding ...')
    model = Doc2Vec(documents=corpus, window=5, min_count=10, workers=4,
                    vector_size=EMBEDDING_DIM, epochs=200, sample=1e-4, negative=5, dm=0)
    print('[-] save doc2vec model')
    model.save(_D2V_MODEL_FILE)

def _create_s2v_model():
    print('[#] Create sent2vec model')
    if not isfile(_CORPUS_FILE):
        print('[!] Please check the corpus file: %s' % _CORPUS_FILE)
        return
    corpus = list()
    with open(_CORPUS_FILE) as f:
        lines = f.readlines()
        idx = 0
        for line in lines:
            temp = line.split('\n')[0].strip()
            sents = temp.split(';')
            for sent in sents:
                corpus.append(TaggedDocument(sent.split(' '), [idx]))
                idx += 1
    print('[-] sent2vec embedding ...')
    model = Doc2Vec(documents=corpus, window=5, min_count=10, workers=4,
                    vector_size=EMBEDDING_DIM, epochs=200, sample=1e-4, negative=5, dm=0)
    print('[-] save sent2vec model')
    model.save(_S2V_MODEL_FILE)


def _create_embedding_matrix(word_index, embed_opt='w2v'):
    print('[#] Create embedding matrix')
    words_size = min(MAX_WORDS, len(word_index)) + 1
    embedding_matrix = np.zeros((words_size, EMBEDDING_DIM))
    if embed_opt == 'w2v':
        if not isfile(_W2V_MODEL_FILE): _create_w2v_model()
        word2vec = KeyedVectors.load_word2vec_format(_W2V_MODEL_FILE)
        cnt = 0
        for word, i in word_index.items():
            if word in word2vec.vocab:
                embedding_matrix[i] = word2vec.word_vec(word)
                cnt += 1
        print(cnt)
    elif embed_opt == 'gv':
        if not isfile(_GV_MODEL_FILE): return
        word2vec = KeyedVectors.load_word2vec_format(_GV_MODEL_FILE)
        cnt = 0
        for word, i in word_index.items():
            if word in word2vec.vocab:
                embedding_matrix[i] = word2vec.word_vec(word)
                cnt += 1
        print(cnt)
    elif embed_opt == 'ft':
        if not isfile(_FT_MODEL_FILE): _create_ft_model()
        ft = FastText.load(_FT_MODEL_FILE)
        cnt = 0
        for word, i in word_index.items():
            if word in ft.wv.vocab:
                embedding_matrix[i] = ft.wv[word]
                cnt += 1
        print(cnt)
    elif embed_opt == 'd2v':
        if not isfile(_D2V_MODEL_FILE): _create_d2v_model()
        doc2vec = Doc2Vec.load(_D2V_MODEL_FILE)
        for word, i in word_index.items():
            if word in doc2vec.wv.vocab:
                embedding_matrix[i] = doc2vec.wv.word_vec(word)
    elif embed_opt == 's2v':
        if not isfile(_S2V_MODEL_FILE): _create_s2v_model()
        sent2vec = Doc2Vec.load(_S2V_MODEL_FILE)
        for word, i in word_index.items():
            if word in sent2vec.wv.vocab:
                embedding_matrix[i] = sent2vec.wv.word_vec(word)
    return embedding_matrix


def load_snippet_data(embed_opt='w2v'):
    print('[*] Load snippet data')
    if not isfile(_DATASET_FILE): _create_data()
    df = pd.read_csv(_DATASET_FILE, sep='\t', usecols=['label', 'snippet'],
                     dtype={'label': int, 'snippet': str})
    df.fillna('', inplace=True)
    print('[-] tokenizing ...')
    tokenizer = Tokenizer(num_words=MAX_WORDS)
    tokenizer.fit_on_texts(df['snippet'])
    snippet = tokenizer.texts_to_sequences(df['snippet'])
    print('[-] post zero padding ... (size: %d)' % SNIPPET_SIZE)
    X = pad_sequences(snippet, maxlen=SNIPPET_SIZE, padding='post')
    df.loc[df['label'] == 2, 'label'] = 1
    y = to_categorical(df['label'], CLASS_NUM)
    tr_X, tr_y, te_X, te_y = _split_data(X, y, TEST_SPLIT, split_shuffle=True)
    embedding_matrix = _create_embedding_matrix(tokenizer.word_index, embed_opt)
    print('[*] Done!!! -> load snippet data\n')
    return (tr_X, tr_y), (te_X, te_y), embedding_matrix


def load_snippet_data_for_kfold(embed_opt='w2v'):
    print('[*] Load snippet data for K-fold cross validation')
    if not isfile(_DATASET_FILE): _create_data()
    df = pd.read_csv(_DATASET_FILE, sep='\t', usecols=['label', 'snippet'],
                     dtype={'label': int, 'snippet': str})
    df.fillna('', inplace=True)
    print('[-] tokenizing ...')
    tokenizer = Tokenizer(num_words=MAX_WORDS)
    tokenizer.fit_on_texts(df['snippet'])
    snippet = tokenizer.texts_to_sequences(df['snippet'])
    print('[-] post zero padding ... (size: %d)' % SNIPPET_SIZE)
    X = pad_sequences(snippet, maxlen=SNIPPET_SIZE, padding='post')
    y = to_categorical(df['label'], CLASS_NUM)
    X, y, kf = _split_data_for_kfold(X, y, k_fold=K_FOLD, split_shuffle=True)
    embedding_matrix = _create_embedding_matrix(tokenizer.word_index, embed_opt)
    print('[*] Done!!! -> load snippet data for K-fold cross validation\n')
    return X, y, kf, embedding_matrix


def add_embedding_layer(embedding_matrix):
    print('[#] add embedding layer...')
    model = Sequential()
    input_dim, output_dim = embedding_matrix.shape
    if STATEFUL:
        model.add(Embedding(input_dim, output_dim, weights=[embedding_matrix],
                            batch_input_shape=(BATCH_SIZE, SNIPPET_SIZE),
                            input_length=SNIPPET_SIZE, trainable=False))
    else:
        model.add(Embedding(input_dim, output_dim, weights=[embedding_matrix],
                            input_shape=(SNIPPET_SIZE,),
                            input_length=SNIPPET_SIZE, trainable=False))
    return model

def lstm(embedding_matrix):
    print('[*] Start to build lstm model')
    model = add_embedding_layer(embedding_matrix)
    model.add(LSTM(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                   kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG)))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Dense(CLASS_NUM, activation='softmax'))
    adam = Adam(lr=0.001)
    model.compile(loss='categorical_crossentropy', optimizer=adam, metrics=['accuracy'])
    model.summary()
    print('[*] Done!!! -> build lstm model\n')
    return model

def blstm(embedding_matrix):
    print('[*] Start to build bidirectional lstm model')
    model = add_embedding_layer(embedding_matrix)
    model.add(Bidirectional(LSTM(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                                 kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG))))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Dense(CLASS_NUM, activation='softmax'))
    adam = Adam(lr=0.001)
    model.compile(loss='categorical_crossentropy', optimizer=adam, metrics=['accuracy'])
    model.summary()
    print('[*] Done!!! -> build bidirectional lstm model\n')
    return model

def multi_lstm(embedding_matrix):
    print('[*] Start to build multi-layer lstm model')
    model = add_embedding_layer(embedding_matrix)
    model.add(LSTM(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                   kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                   return_sequences=True))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(LSTM(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                   kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                   return_sequences=True))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(LSTM(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                   kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                   return_sequences=False))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Dense(CLASS_NUM, activation='softmax'))
    adam = Adam(lr=0.001)
    model.compile(loss='categorical_crossentropy', optimizer=adam, metrics=['accuracy'])
    model.summary()
    print('[*] Done!!! -> build multi-layer lstm model\n')
    return model

def multi_blstm(embedding_matrix):
    print('[*] Start to build multi-layer bidirectional lstm model')
    model = add_embedding_layer(embedding_matrix)
    model.add(Bidirectional(LSTM(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                                 kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                                 return_sequences=True)))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Bidirectional(LSTM(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                                 kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                                 return_sequences=True)))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Bidirectional(LSTM(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                                 kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                                 return_sequences=False)))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Dense(CLASS_NUM, activation='softmax'))
    adam = Adam(lr=0.001)
    model.compile(loss='categorical_crossentropy', optimizer=adam, metrics=['accuracy'])
    model.summary()
    print('[*] Done!!! -> build multi-layer bidirectional lstm model\n')
    return model

def gru(embedding_matrix):
    print('[*] Start to build lstm model')
    model = add_embedding_layer(embedding_matrix)
    model.add(GRU(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                  kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG)))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Dense(CLASS_NUM, activation='softmax'))
    adam = Adam(lr=0.001)
    model.compile(loss='categorical_crossentropy', optimizer=adam, metrics=['accuracy'])
    model.summary()
    print('[*] Done!!! -> build lstm model\n')
    return model

def bgru(embedding_matrix):
    print('[*] Start to build bidirectional lstm model')
    model = add_embedding_layer(embedding_matrix)
    model.add(Bidirectional(GRU(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                                kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG))))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Dense(CLASS_NUM, activation='softmax'))
    adam = Adam(lr=0.001)
    model.compile(loss='categorical_crossentropy', optimizer=adam, metrics=['accuracy'])
    model.summary()
    print('[*] Done!!! -> build bidirectional lstm model\n')
    return model

def multi_gru(embedding_matrix):
    print('[*] Start to build multi-layer lstm model')
    model = add_embedding_layer(embedding_matrix)
    model.add(GRU(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                  kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                  return_sequences=True))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(GRU(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                  kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                  return_sequences=True))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(GRU(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                  kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                  return_sequences=False))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Dense(CLASS_NUM, activation='softmax'))
    adam = Adam(lr=0.001)
    model.compile(loss='categorical_crossentropy', optimizer=adam, metrics=['accuracy'])
    model.summary()
    print('[*] Done!!! -> build multi-layer lstm model\n')
    return model

def multi_bgru(embedding_matrix):
    print('[*] Start to build multi-layer bidirectional lstm model')
    model = add_embedding_layer(embedding_matrix)
    model.add(Bidirectional(GRU(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                                kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                                return_sequences=True)))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Bidirectional(GRU(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                                kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                                return_sequences=True)))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Bidirectional(GRU(HIDDEN_DIM, kernel_initializer='he_normal', stateful=STATEFUL,
                                kernel_regularizer=regularizers.l1_l2(l1=L1_REG, l2=L2_REG),
                                return_sequences=False)))
    model.add(Activation('relu'))
    model.add(Dropout(DROPOUT_RATE))
    model.add(Dense(CLASS_NUM, activation='softmax'))
    adam = Adam(lr=0.001)
    model.compile(loss='categorical_crossentropy', optimizer=adam, metrics=['accuracy'])
    model.summary()
    print('[*] Done!!! -> build multi-layer bidirectional lstm model\n')
    return model

def fit_and_result(model, tr_X, tr_y, te_X, te_y):
    print('[*] Start to fit model')
    if EARLYSTOP:
        early_stopping = EarlyStopping(monitor='loss', patience=10)
    else:
        early_stopping = None

    sme = SMOTEENN(random_state=42)
    tr_X, tr_y = sme.fit_resample(tr_X, tr_y)

    hist = model.fit(tr_X, tr_y, validation_split=VALID_SPLIT, epochs=EPOCH_SIZE,
                     batch_size=BATCH_SIZE, shuffle=False, callbacks=[early_stopping])
    print('[-] make result report')
    pred_y = np.argmax(model.predict(te_X, batch_size=BATCH_SIZE), axis=1)
    te_y = np.argmax(te_y, axis=1)
    print('[*] Done!!! -> fit and result\n')
    return classification_report(te_y, pred_y), hist

def kfold_cross_validation(model, X, y, kf):
    result = list()
    early_stopping = EarlyStopping(monitor='loss', patience=10)
    for train, valid in kf.split(X, y):
        sme = SMOTEENN(random_state=42)
        tr_X, tr_y = sme.fit_resample(X[train], y[train])
        model.fit(tr_X, tr_y, epochs=EPOCH_SIZE, batch_size=BATCH_SIZE,
                  shuffle=False, callbacks=[early_stopping])
        temp = '%.4f' % (model.evaluate(X[valid], y[valid], batch_size=BATCH_SIZE)[1])
        result.append(temp)
    return result

def print_hyperprameter():
    print('[*] Hyperprameter')
    print('[-] Embedding Model:', EMBEDDING_MODEL)
    print('[-] Input Shape(Batch, TimeStep, Vector_Size):', BATCH_SIZE, SNIPPET_SIZE, EMBEDDING_DIM)
    print('[-] Output Shape:', CLASS_NUM)
    print('[-] Hiden layer Dimension:', HIDDEN_DIM)
    print('[-] Stateful:', STATEFUL)
    print('[-] Dropout rate:', DROPOUT_RATE)
    print('[-] Epoch size:', EPOCH_SIZE)
    print('[-] Split(test, validation):', TEST_SPLIT, VALID_SPLIT)
    print('')

def get_image_path():
    img_path = os.getcwd() + '/image/'
    if not isdir(img_path):
        os.mkdir(img_path)
    return img_path

def create_accuracy_graph(reports, model_name, show=False):
    dirpath = get_image_path()
    title = model_name + '_accuracy'
    filename = dirpath + datetime.datetime.now().strftime("%y%m%d_%H%M_") + title + '.png'
    accuracy = reports[model_name]['history'].history['accuracy']
    val_accuracy = reports[model_name]['history'].history['val_accuracy']
    plt.title(title)
    plt.plot(accuracy, label='train')
    plt.plot(val_accuracy, label='test')
    plt.ylabel('accuracy')
    plt.xlabel('epoch')
    plt.legend(loc='upper left')
    plt.savefig(filename)
    if show: plt.show()
    plt.close()

def create_loss_graph(reports, model_name, show=False):
    dirpath = get_image_path()
    title = model_name + '_loss'
    filename = dirpath + datetime.datetime.now().strftime("%y%m%d_%H%M_") + title + '.png'
    loss = reports[model_name]['history'].history['loss']
    val_loss = reports[model_name]['history'].history['val_loss']
    plt.title(title)
    plt.plot(loss, label='train')
    plt.plot(val_loss, label='test')
    plt.ylabel('loss')
    plt.xlabel('epoch')
    plt.legend(loc='upper left')
    plt.savefig(filename)
    if show: plt.show()
    plt.close()

def create_compare_accuracy_graph(reports, show=False):
    dirpath = get_image_path()
    filename = dirpath + datetime.datetime.now().strftime("%y%m%d_%H%M_") + 'accuracy_compare.png'
    plt.title('Compare model_accuracy')
    plt.ylabel('accuracy')
    plt.xlabel('epoch')
    for model_name, report in reports.items():
        accuracy = report['history'].history['accuracy']
        plt.plot(accuracy, label=model_name)
    plt.legend(loc='upper left')
    plt.savefig(filename)
    if show: plt.show()
    plt.close()

def create_compare_loss_graph(reports, show=False):
    dirpath = get_image_path()
    filename = dirpath + datetime.datetime.now().strftime("%y%m%d_%H%M_") + 'loss_compare.png'
    plt.title('Compare model_loss')
    plt.ylabel('loss')
    plt.xlabel('epoch')
    for model_name, report in reports.items():
        loss = report['history'].history['loss']
        plt.plot(loss, label=model_name)
    plt.legend(loc='upper left')
    plt.savefig(filename)
    if show: plt.show()
    plt.close()

def run(opt='training'):
    models = {
        # 'lstm': lstm, 'blstm': blstm, 'multi_lstm': multi_lstm, 'multi_lstm': multi_lstm,
        # 'gru': gru, 'bgru': bgru, 'multi_gru': multi_gru, 'multi_bgru': multi_bgru
        'BLSTM': blstm, 'BGRU': bgru
    }
    reports = dict()
    if opt=='training':
        (tr_X, tr_y), (te_X, te_y), embedding_matrix = load_snippet_data(EMBEDDING_MODEL)
        for model_name, model_func in models.items():
            temp = dict()
            model = model_func(embedding_matrix)
            result, history = fit_and_result(model, tr_X, tr_y, te_X, te_y)
            temp.update({'result': result, 'history': history})
            reports[model_name] = temp
    elif opt=='kfold':
        X, y, kf, embedding_matrix = load_snippet_data_for_kfold(EMBEDDING_MODEL)
        for model_name, model_func in models.items():
            temp = dict()
            model = model_func(embedding_matrix)
            result = kfold_cross_validation(model, X, y, kf)
            temp.update({'result': result})
            reports[model_name] = temp
    else:
        print('[!] Please check the opt name:', opt)
        return
    print_hyperprameter()
    for model_name in models.keys():
        print('[*]', model_name)
        print(reports[model_name]['result'])
        create_accuracy_graph(reports, model_name)
        create_loss_graph(reports, model_name)
    create_compare_accuracy_graph(reports)
    create_compare_loss_graph(reports)

if __name__=='__main__':
    opt='training'
    run(opt)