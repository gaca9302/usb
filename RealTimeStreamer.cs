using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Net.Sockets; 
using System.Security.Cryptography; // Для дельта-сжатия по MD5
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using NAudio.Wave;
using NAudio.Wave.SampleProviders;

namespace ScreenAudioStreamer;

public class RealTimeStreamer : IDisposable
{
    private TcpClient? _tcpClient;
    private StreamWriter? _networkWriter;

    private WasapiLoopbackCapture? _audioCapture;
    private BufferedWaveProvider? _audioBuffer;
    private ISampleProvider? _resampledAudio;
    private CancellationTokenSource? _cts;
    private Channel<StreamMessage>? _channel;

    private Task? _senderTask;
    private Task? _screenTask;
    private Task? _audioTask;

    private volatile bool _running;

    public event Action<string>? StatusChanged;

    public async Task StartAsync(string host, int port)
    {
        if (_running)
            return;

        try
        {
            StatusChanged?.Invoke($"Подключение к {host}:{port} через TCP...");

            _tcpClient = new TcpClient();
            await _tcpClient.ConnectAsync(host, port);
            
            // ИСПРАВЛЕНО: Отключаем отправку UTF-8 BOM, передавая false, чтобы Python не выдавал ошибку декодирования
            var utf8WithoutBom = new UTF8Encoding(false);
            _networkWriter = new StreamWriter(_tcpClient.GetStream(), utf8WithoutBom) { AutoFlush = true };

            _cts = new CancellationTokenSource();

            _channel = Channel.CreateBounded<StreamMessage>(
                new BoundedChannelOptions(64)
                {
                    FullMode = BoundedChannelFullMode.DropOldest,
                    SingleReader = true,
                    SingleWriter = false
                }
            );

            _running = true;

            _senderTask = SendLoopAsync(_cts.Token);

            InitializeSystemAudio();

            _audioTask = CaptureAudioAsync(_cts.Token);
            _audioCapture!.StartRecording();

            _screenTask = CaptureScreenAsync(_cts.Token);

            StatusChanged?.Invoke("Трансляция запущена (TCP)");
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke("Ошибка запуска: " + ex.Message);
            await StopAsync();
            throw;
        }
    }

    private void InitializeSystemAudio()
    {
        _audioCapture = new WasapiLoopbackCapture();
        WaveFormat inputFormat = _audioCapture.WaveFormat;

        _audioBuffer = new BufferedWaveProvider(inputFormat)
        {
            BufferDuration = TimeSpan.FromSeconds(5),
            DiscardOnBufferOverflow = true,
            ReadFully = false
        };

        ISampleProvider sampleProvider = _audioBuffer.ToSampleProvider();

        if (sampleProvider.WaveFormat.Channels == 2)
        {
            sampleProvider = new StereoToMonoSampleProvider(sampleProvider);
        }
        else if (sampleProvider.WaveFormat.Channels != 1)
        {
            throw new NotSupportedException("Поддерживается только моно или стерео звук.");
        }

        _resampledAudio = new WdlResamplingSampleProvider(sampleProvider, 16000);

        _audioCapture.DataAvailable += (sender, e) =>
        {
            if (!_running || _audioBuffer == null) return;
            if (e.BytesRecorded <= 0) return;

            try
            {
                _audioBuffer.AddSamples(e.Buffer, 0, e.BytesRecorded);
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke("Ошибка получения системного звука: " + ex.Message);
            }
        };

        _audioCapture.RecordingStopped += (sender, e) =>
        {
            if (e.Exception != null && _running)
            {
                StatusChanged?.Invoke("Ошибка системного звука: " + e.Exception.Message);
            }
        };
    }

    private async Task CaptureAudioAsync(CancellationToken cancellationToken)
    {
        if (_resampledAudio == null) return;

        const int samplesPerChunk = 320;
        float[] samples = new float[samplesPerChunk];

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                int samplesRead = _resampledAudio.Read(samples, 0, samples.Length);
                if (samplesRead <= 0)
                {
                    await Task.Delay(10, cancellationToken);
                    continue;
                }

                short[] pcmData = new short[samplesRead];
                for (int i = 0; i < samplesRead; i++)
                {
                    float value = Math.Clamp(samples[i], -1.0f, 1.0f);
                    pcmData[i] = (short)(value * 32767);
                }

                byte[] audioBytes = new byte[samplesRead * sizeof(short)];
                Buffer.BlockCopy(pcmData, 0, audioBytes, 0, audioBytes.Length);

                string base64 = Convert.ToBase64String(audioBytes);

                _channel?.Writer.TryWrite(new StreamMessage
                {
                    type = "audio_chunk",
                    data = base64
                });
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                StatusChanged?.Invoke("Ошибка обработки звука: " + ex.Message);
                await Task.Delay(100, cancellationToken);
            }
        }
    }


	private async Task CaptureScreenAsync(CancellationToken cancellationToken)
	{
		string lastFrameHash = string.Empty;

		while (!cancellationToken.IsCancellationRequested)
		{
			try
			{
				Rectangle bounds = Screen.PrimaryScreen!.Bounds;

				// Захват экрана в исходном разрешении
				using Bitmap original = new Bitmap(bounds.Width, bounds.Height);

				using (Graphics g = Graphics.FromImage(original))
				{
					g.CopyFromScreen(
						bounds.Left,
						bounds.Top,
						0,
						0,
						bounds.Size
					);
				}

				// Уменьшение до ширины 1280
				int maxWidth = 1280;

				double scale = Math.Min(
					1.0,
					(double)maxWidth / bounds.Width
				);

				int width = Math.Max(1, (int)(bounds.Width * scale));
				int height = Math.Max(1, (int)(bounds.Height * scale));

				using Bitmap bitmap = new Bitmap(width, height);

				using (Graphics graphics = Graphics.FromImage(bitmap))
				{
					graphics.InterpolationMode =
						System.Drawing.Drawing2D.InterpolationMode.HighQualityBilinear;

					graphics.DrawImage(
						original,
						new Rectangle(0, 0, width, height)
					);

					// Отображение курсора
					try
					{
						Point cursorPosition = Cursor.Position;

						int cursorX = (int)((cursorPosition.X - bounds.Left) * scale);
						int cursorY = (int)((cursorPosition.Y - bounds.Top) * scale);

						using Bitmap cursorBitmap = new Bitmap(
							Cursors.Default.Size.Width,
							Cursors.Default.Size.Height
						);

						using (Graphics cursorGraphics = Graphics.FromImage(cursorBitmap))
						{
							Cursors.Default.Draw(
								cursorGraphics,
								new Rectangle(Point.Empty, Cursors.Default.Size)
							);
						}

						graphics.DrawImage(
							cursorBitmap,
							cursorX,
							cursorY,
							cursorBitmap.Width * (float)scale,
							cursorBitmap.Height * (float)scale
						);
					}
					catch { }
				}

				// JPEG-кодирование
				using MemoryStream ms = new MemoryStream();

				ImageCodecInfo codec = ImageCodecInfo.GetImageEncoders()
					.First(x => x.FormatID == ImageFormat.Jpeg.Guid);

				using EncoderParameters parameters = new EncoderParameters(1);

				parameters.Param[0] = new EncoderParameter(
					System.Drawing.Imaging.Encoder.Quality,
					30L
				);

				bitmap.Save(ms, codec, parameters);

				byte[] frameBytes = ms.ToArray();

				// Проверка изменений кадра
				string currentFrameHash = BitConverter.ToString(
					MD5.HashData(frameBytes)
				);

				if (currentFrameHash == lastFrameHash)
				{
					await Task.Delay(200, cancellationToken);
					continue;
				}

				lastFrameHash = currentFrameHash;

				string base64 = Convert.ToBase64String(frameBytes);

				_channel?.Writer.TryWrite(new StreamMessage
				{
					type = "video_frame",
					data = base64
				});
			}
			catch (OperationCanceledException)
			{
				break;
			}
			catch (Exception ex)
			{
				StatusChanged?.Invoke("Ошибка экрана: " + ex.Message);
			}

			// Ограничение частоты захвата примерно до 5 FPS
			try
			{
				await Task.Delay(200, cancellationToken);
			}
			catch (OperationCanceledException)
			{
				break;
			}
		}
	}


    private async Task SendLoopAsync(CancellationToken cancellationToken)
    {
        if (_channel == null) return;

        try
        {
            // ИСПРАВЛЕНО: Восстановлен цикл чтения из Channel и отправки JSON пакета с разделителем '\n'
            await foreach (var message in _channel.Reader.ReadAllAsync(cancellationToken))
            {
                if (_networkWriter == null || _tcpClient == null || !_tcpClient.Connected) 
                    continue;

                string jsonString = JsonSerializer.Serialize(message);
                await _networkWriter.WriteLineAsync(jsonString); // Пишет JSON и добавляет \n в конец
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            StatusChanged?.Invoke("Ошибка сети (TCP): " + ex.Message);
        }
    }

    public async Task StopAsync()
    {
        if (!_running) return;
        _running = false;

        try { _cts?.Cancel(); } catch { }

        if (_audioCapture != null)
        {
            try { _audioCapture.StopRecording(); _audioCapture.Dispose(); } catch { }
        }

        try
        {
            if (_senderTask != null) await _senderTask;
            if (_screenTask != null) await _screenTask;
            if (_audioTask != null) await _audioTask;
        }
        catch { }

        // ИСПРАВЛЕНО: Закрытие потоков записи и сетевого сокета
        _networkWriter?.Close();
        _tcpClient?.Close();

        _cts?.Dispose();
        _audioBuffer = null;
        _resampledAudio = null;

        StatusChanged?.Invoke("Трансляция остановлена");
    }

    private ImageCodecInfo? GetEncoder(ImageFormat format)
    {
        ImageCodecInfo[] codecs = ImageCodecInfo.GetImageEncoders();
        foreach (ImageCodecInfo codec in codecs)
        {
            if (codec.FormatID == format.Guid) return codec;
        }
        return null;
    }

    public void Dispose()
    {
        StopAsync().GetAwaiter().GetResult();
    }
}

public class StreamMessage

{
    public string type { get; set; } = string.Empty;
    public string data { get; set; } = string.Empty;
}