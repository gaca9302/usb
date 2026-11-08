using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ScreenAudioStreamer;

internal static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        string host = "127.0.0.1";
        int port = 8080;

        foreach (string arg in args)
        {
            if (arg.StartsWith("host=", StringComparison.OrdinalIgnoreCase))
                host = arg.Substring(5);

            if (arg.StartsWith("port=", StringComparison.OrdinalIgnoreCase))
            {
                if (!int.TryParse(arg.Substring(5), out port) ||
                    port < 1 || port > 65535)
                {
                    // В фоновом режиме MessageBox убран, чтобы процесс не зависал скрытно.
                    return; 
                }
            }
        }

        ApplicationConfiguration.Initialize();

        // Запускаем скрытый контекст без отображения форм на экране
        var context = new BackgroundApplicationContext(host, port);
        Application.Run(context);
    }
}

// Кастомный контекст для работы приложения строго невидимо в фоне
public class BackgroundApplicationContext : ApplicationContext
{
    private readonly RealTimeStreamer _streamer = new();
    private readonly string _host;
    private readonly int _port;

    public BackgroundApplicationContext(string host, int port)
    {
        // ИСПРАВЛЕНО: Сохраняем чистые host и port для быстрого TCP
        _host = host;
        _port = port;

        // Подписываемся на события изменения статуса для корректной обработки сбоев сети
        _streamer.StatusChanged += message =>
        {
            if (message.Contains("Ошибка"))
            {
                // При необходимости логируем ошибку в файл, но не выводим окон
            }
        };

        // Запуск асинхронного стриминга
        _ = StartStreamingAsync();
    }

    private async Task StartStreamingAsync()
    {
        try
        {
            // ИСПРАВЛЕНО: Передаем host и port раздельно в новый TCP-клиент
            await _streamer.StartAsync(_host, _port);
        }
        catch
        {
            // Логика обработки критической ошибки при подключении
            ExitThread();
        }
    }

    // Метод корректного завершения (вызовется, если процесс убивают или стрим остановлен)
    protected override async void Dispose(bool disposing)
    {
        if (disposing)
        {
            await _streamer.StopAsync();
        }
        base.Dispose(disposing);
    }
}