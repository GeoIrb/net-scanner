# net-scanner
 
Пакет для сканирования сети, обертка над `nmap`

Пример использования

```golang
	scan := scanner.NewNetScanner(time.Minute).
		WithTargets("192.168.0.106/24").
		WithPingScan()

	state, events, err := scan.Run(context.Background())
````

При запуске сканера `Run`, возращается состояние сети `state` на момент запуска сканера и канал `events`, в который будут приходить изменения в состоянии сети, если сравнивать с предыдущим состоянием

Для получения состояния сети после последнего сканировния

```golang
    state := scan.GetState()
```