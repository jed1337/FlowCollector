class ArffWriter():
   ATTRIBUTE = "@attribute"

   def __init__(self, path, features):
      self.path = path
      self.features = features


   def _format_headers(self):
      return [" ".join([ArffWriter.ATTRIBUTE, feature.data_type_holder().name, feature.data_type_holder().type]) for feature in
              self.features]


   def write_headers(self):
      with open(self.path, 'w') as file:
         file.write("\n".join(self._format_headers()))


   def write_data(self, flows):
      # with open(self.path, 'w') as file:

      #Fix
      for packets in flows.items():
         feature_string=[feature.action(packets) for feature in self.features]

      return ",".join(map(str, feature_string))