#!/bin/sh

# Запуск с конфигом
python3 ./DepCrawler.py --config "./configs/aks-dispatch.json" 

# Запуск с фильтрацией 
# Только ошибки
#python3 ./DepCrawler.py --config "./night.json" --error

# Ошибки и предупреждения
#python3 ./DepCrawler.py --config "./night.json" --warning

# Без фильтра
#python3 ./DepCrawler.py --config "./night.json" --info

# Запуск с показом диаграммы
#python3 ./DepCrawler.py --config "./night.json" --warning --diag
