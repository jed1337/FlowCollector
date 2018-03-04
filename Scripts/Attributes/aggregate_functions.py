import numpy as np

def max_agg(arr):
   return max(arr, default=0)


def min_agg(arr):
   return min(arr, default=0)


def mean_agg(arr):
   if not arr:
      return 0
   return np.mean(arr)


def std_agg(arr):
   if not arr:
      return 0
   return np.std(arr)


def var_agg(arr):
   if not arr:
      return 0
   return np.var(arr)


def no_agg(arr):
   return arr