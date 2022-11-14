from pygooglenews import GoogleNews
import pandas as pd
def scrap_news(url):   
  df = pd.DataFrame({})
  l1=[]
  l2=[]
  l3=[]
  gn = GoogleNews()
  s = gn.search(url)
  entries=s['entries']
  for detail in entries:
   a=detail["link"]
   l1.append(a)
  for detail in entries:
   b=detail["title"]
   l2.append(b)
  for detail in entries:
   c=detail["published"]
   l3.append(c)
  df=pd.DataFrame({'link':l1,'title':l2,'published':l3})
  print(df)
  return df
