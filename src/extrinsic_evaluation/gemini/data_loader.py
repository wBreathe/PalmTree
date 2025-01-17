""""
Here we implement a class for loading data.
"""

import torch
from torch.autograd import Variable
from vocab import *
from config import *
import numpy as np
import random
import re

np.random.seed(0)


class DataLoader:
    EOS = 0  # to mean end of sentence
    UNK = 1  # to mean unknown token

    maxlen = MAXLEN

    def __init__(self, text_file=None, sentences=None, word_dict=None):

        if text_file:
            sentences = []
            for txt_file in text_file:
                print("Loading text file at {}".format(txt_file))
                with open(txt_file, "rt") as f:
                    text = f.readlines()
                    for i, line in enumerate(text):
                        if i % 2:
                            sentences.extend(line.strip().split(';'))
                print("Making dictionary for these words")
            word_dict = build_and_save_dictionary(sentences, source="data/instruction")

        assert sentences and word_dict, "Please provide the file to extract from or give sentences and word_dict"

        self.sentences = sentences
        self.word_dict = word_dict
        # print("Making reverse dictionary")
        self.revmap = list(self.word_dict.items())

        self.lengths = [len(sent) for sent in self.sentences]

    def convert_sentence_to_indices(self, sentence):
        sentence = re.split(',| ', sentence)
        tokn_lst = []
        for s in sentence:
            tokn_lst.extend(re.split('([0-9A-Za-z@_.]+)', s))
        tokn_lst = [t for t in tokn_lst if t]
        indices = [
                      # assign an integer to each word, if the word is too rare assign unknown token
                      self.word_dict.get(w) if self.word_dict.get(w, VOCAB_SIZE + 1) < VOCAB_SIZE else self.UNK

                      for w in tokn_lst  # split into words on spaces
                  ][: self.maxlen - 1]  # take only maxlen-1 words per sentence at the most.

        # last words are EOS
        indices += [self.EOS] * (self.maxlen - len(indices))

        indices = np.array(indices)
        indices = Variable(torch.from_numpy(indices))
        return indices

    def convert_indices_to_sentences(self, indices):
        def convert_index_to_word(idx):

            idx = idx.data.item()
            if idx == 0:
                return "EOS"
            elif idx == 1:
                return "UNK"
            
            search_idx = idx - 2
            if search_idx >= len(self.revmap):
                return "NA"
            
            word, idx_ = self.revmap[search_idx]

            assert idx_ == idx
            return word

        words = [convert_index_to_word(idx) for idx in indices]

        return " ".join(words)

    def fetch_batch(self, batch_size):

        first_index = random.randint(0, len(self.sentences) - batch_size)
        batch = []
        lengths = []

        for i in range(first_index, first_index + batch_size):
            sent = self.sentences[i]
            ind = self.convert_sentence_to_indices(sent)
            if USE_CUDA:
                ind = ind.cuda(CUDA_DEVICE)
            batch.append(ind)
            lengths.append(min(len(sent.split()), MAXLEN))

        batch = torch.stack(batch)
        lengths = np.array(lengths)

        return batch, lengths
