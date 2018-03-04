import Attributes.feature as feature

class ArffWriter():
   NEW_LINE  = "\n"

   RELATION  = "@relation relation"
   ATTRIBUTE = "@attribute"
   DATA      = "@data"


   def __init__(self, path, c_attribute, features):
      """
      :param path: Path to the arff file
      :param c_attribute: Class attribute (normal,slowHeaders,slowRead,tcpFlood,udpFlood,httpFlood)
      :param features: The features to extract implemented in Scripts/Attributes/feature.py
      """
      self.path = path
      self.c_attribute = ","+c_attribute #The "," is there since the c_attribute is always gonna be appended to the data
      self.features = features


   def _write_attribute_name(self):
      """:return: "@attribute (feature name) (data type)" """
      attributes = [" ".join([ArffWriter.ATTRIBUTE, feature.data_type_holder().name, feature.data_type_holder().type])
                    for feature in self.features]
      attributes.append("@attribute isAttack {normal,slowHeaders,slowRead,tcpFlood,udpFlood,httpFlood}")
      return attributes


   def write_headers(self):
      with open(self.path, 'w') as file:
         file.write(ArffWriter.RELATION)
         file.write(ArffWriter.NEW_LINE)
         file.write("\n".join(self._write_attribute_name()))
         file.write(ArffWriter.NEW_LINE)
         file.write(ArffWriter.DATA)
         file.write(ArffWriter.NEW_LINE)


   def write_data(self, flows):
      with open(self.path, 'a+') as file:
         for key, packets in flows.items():
            print("Current key: %s" %key)
            feature_string=[feature.action(packets) for feature in self.features]
            file.write(",".join(map(str, feature_string)))
            file.write(self.c_attribute)
            file.write(ArffWriter.NEW_LINE)