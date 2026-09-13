// Состояние клиента
let ws = null;
let myNickname = null;
let mySignKey = null;     // Закрытый ключ для цифровой подписи (RSASSA-PKCS1-v1_5 CryptoKey)
let myDecryptKey = null;  // Закрытый ключ для расшифровки сообщений (RSA-OAEP CryptoKey)
let myCertPem = null;     // X.509 сертификат текущего пользователя в формате PEM
let peerPublicKeys = {};  // Кэш открытых ключей собеседников: nickname -> RSA-OAEP CryptoKey
let pendingMessages = {}; // Очередь исходящих сообщений, ожидающих получения ключа: nickname -> [text, ...]
let pendingPkcs8Pem = null; // Временный закрытый ключ до подтверждения выпуска сертификата от CA

// Вывод сообщения в окно системного лога в интерфейсе
function addLog(msg) {
  const box = document.getElementById("log");
  const d = new Date();
  const timeStr = d.toTimeString().split(' ')[0];
  box.textContent += `[${timeStr}] ${msg}\n`;
  box.scrollTop = box.scrollHeight;
}

// Обновление индикатора сетевого статуса и доступности кнопок управления
function setStatus(text, isOnline) {
  const badge = document.getElementById("statusBadge");
  badge.textContent = text;
  badge.className = isOnline ? "status-badge online" : "status-badge";
  document.getElementById("btnConnect").disabled = isOnline;
  document.getElementById("btnDisconnect").disabled = !isOnline;
  document.getElementById("btnSend").disabled = !isOnline;
}

// Автоматическое заполнение хоста и порта сервера из адресной строки браузера
if (window.location.protocol.startsWith('http')) {
  document.getElementById("host").value = window.location.hostname || "127.0.0.1";
  document.getElementById("port").value = window.location.port || "8888";
}

// Вспомогательные функции преобразования бинарных буферов и Base64
function bufToB64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function b64ToBuf(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return b64ToBuf(b64);
}

function derToPem(der, label) {
  const b64 = bufToB64(der);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

function concatBytes(...arrays) {
  const totalLen = arrays.reduce((acc, curr) => acc + curr.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// Управление криптографическими ключами и сертификатами
async function loadOrGenerateKeys(nick) {
  const storedPkcs8 = localStorage.getItem(`sun_in_key_${nick}`);
  const storedCert = localStorage.getItem(`sun_in_cert_${nick}`);

  // Если ключи и сертификат уже сохранены в браузере, используем их
  if (storedPkcs8 && storedCert) {
    addLog(`[CRYPTO] Загрузка сохраненных ключей для '${nick}'...`);
    const pkcs8Bytes = pemToDer(storedPkcs8);
    mySignKey = await window.crypto.subtle.importKey(
      "pkcs8",
      pkcs8Bytes,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );
    myDecryptKey = await window.crypto.subtle.importKey(
      "pkcs8",
      pkcs8Bytes,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
    myCertPem = storedCert;
    return { needEnroll: false };
  }

  // Первичная генерация связки RSA-2048 ключей через WebCrypto
  addLog(`[CRYPTO] Генерация новой RSA ключевой пары для '${nick}' (WebCrypto)...`);
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );

  mySignKey = keyPair.privateKey;
  const pkcs8Raw = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  // Импорт закрытого ключа для расшифровки сообщений по схеме RSA-OAEP
  myDecryptKey = await window.crypto.subtle.importKey(
    "pkcs8",
    pkcs8Raw,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );

  pendingPkcs8Pem = derToPem(new Uint8Array(pkcs8Raw), "PRIVATE KEY");

  // Формирование запроса на сертификат PKCS#10 (CSR) через библиотеку x509
  addLog(`[CRYPTO] Создание PKCS#10 CSR через библиотеку x509...`);
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${nick}, O=SUN_IN, C=RU`,
    keys: keyPair,
    signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }
  });
  const csrPem = csr.toString("pem");

  return { needEnroll: true, csrPem };
}

// Подключение к WebSocket серверу
async function connectChat() {
  const nick = document.getElementById("nickname").value.trim();
  if (!nick) {
    addLog("[ERR] Введите никнейм перед подключением");
    return;
  }
  const host = document.getElementById("host").value.trim() || "127.0.0.1";
  const port = document.getElementById("port").value.trim() || "8888";
  myNickname = nick;

  if (ws) {
    ws.close();
  }

  const wsUrl = `ws://${host}:${port}`;
  addLog(`[NET] Подключение к ${wsUrl}...`);
  try {
    ws = new WebSocket(wsUrl);
  } catch (e) {
    addLog(`[ERR] Ошибка WebSocket: ${e.message}`);
    return;
  }

  ws.onopen = async function () {
    addLog("[NET] WebSocket соединение установлено");
    try {
      const res = await loadOrGenerateKeys(nick);
      if (res.needEnroll) {
        // Новый пользователь: запрашиваем выпуск сертификата
        addLog("[AUTH] Запрос выпуска сертификата (cert_enroll)...");
        sendPacket({ type: "cert_enroll", nickname: nick, csr: res.csrPem });
      } else {
        // Повторный вход: авторизация с существующим сертификатом
        addLog("[AUTH] Отправка auth_init с существующим сертификатом...");
        sendPacket({ type: "auth_init", nickname: nick, client_cert: myCertPem });
      }
    } catch (e) {
      addLog(`[ERR] Ошибка подготовки ключей: ${e.message}`);
    }
  };

  ws.onmessage = async function (event) {
    try {
      const packet = JSON.parse(event.data);
      await handlePacket(packet);
    } catch (e) {
      addLog(`[ERR] Ошибка обработки пакета: ${e}`);
    }
  };

  ws.onerror = function () {
    addLog("[ERR] Ошибка сети WebSocket");
  };

  ws.onclose = function () {
    addLog("[NET] Соединение с сервером закрыто");
    setStatus("DISCONNECTED", false);
    ws = null;
  };
}

// Отключение от чата
function disconnectChat() {
  if (ws) {
    ws.close();
    ws = null;
  }
  setStatus("DISCONNECTED", false);
}

// Безопасная отправка JSON-пакета на сервер
function sendPacket(packet) {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    addLog("[ERR] Нет активного подключения к серверу");
    return false;
  }
  ws.send(JSON.stringify(packet));
  return true;
}

// Главный диспетчер входящих пакетов
async function handlePacket(packet) {
  if (packet.type === 'cert_enroll_response') {
    // Сертификат успешно подписан и выдан сервером CA
    addLog("[AUTH] Сертификат успешно получен от CA сервера");
    myCertPem = packet.client_cert;
    if (pendingPkcs8Pem) {
      // Сохраняем связку ключа и сертификата в локальное хранилище браузера
      localStorage.setItem(`sun_in_key_${packet.nickname}`, pendingPkcs8Pem);
      localStorage.setItem(`sun_in_cert_${packet.nickname}`, myCertPem);
      pendingPkcs8Pem = null;
    }
    addLog("[AUTH] Отправка auth_init...");
    sendPacket({ type: "auth_init", nickname: packet.nickname, client_cert: myCertPem });

  } else if (packet.type === 'auth_challenge') {
    // Сервер прислал случайный nonce для проверки владения закрытым ключом
    addLog("[AUTH] Получен challenge от сервера, вычисление подписи...");
    try {
      const nonceBytes = b64ToBuf(packet.nonce);
      const signature = await window.crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
        mySignKey,
        nonceBytes
      );
      sendPacket({ type: "auth_proof", signature: bufToB64(signature) });
    } catch (e) {
      addLog(`[ERR] Ошибка подписи challenge: ${e.message}`);
    }

  } else if (packet.type === 'event') {
    // Системные события чата
    if (packet.event === 'auth_success') {
      setStatus(`ONLINE: ${myNickname}`, true);
      addLog(`[OK] ✓ ${packet.text || "Успешная авторизация!"}`);
    } else if (packet.event === 'users_list') {
      addLog(`[EVT] ${packet.text}`);
      updateUsersList(packet.text);
    } else if (packet.event === 'user_joined') {
      addLog(`[EVT] ► ${packet.text || packet.nickname + ' присоединился'}`);
    } else if (packet.event === 'user_left') {
      addLog(`[EVT] ◄ ${packet.text || packet.nickname + ' покинул чат'}`);
    } else {
      addLog(`[EVT] ${packet.event}: ${packet.text || ''}`);
    }

  } else if (packet.type === 'key_response') {
    // Получен сертификат и открытый ключ собеседника
    const user = packet.nickname;
    try {
      // Парсинг X.509 сертификата и извлечение открытого ключа RSA-OAEP через библиотеку x509
      const cert = new x509.X509Certificate(packet.client_cert);
      const rsaKey = await cert.publicKey.export(
        { name: "RSA-OAEP", hash: "SHA-256" },
        ["encrypt"]
      );
      peerPublicKeys[user] = rsaKey;
      addLog(`[CRYPTO] Ключ пользователя '${user}' успешно извлечен из сертификата`);

      // Отправляем все отложенные сообщения для этого собеседника
      if (pendingMessages[user] && pendingMessages[user].length > 0) {
        const queue = pendingMessages[user];
        delete pendingMessages[user];
        for (const text of queue) {
          await sendEncryptedMessage(user, text);
        }
      }
    } catch (e) {
      addLog(`[ERR] Ошибка импорта ключа '${user}': ${e.message}`);
    }

  } else if (packet.type === 'message') {
    // Входящее зашифрованное сообщение
    await handleIncomingMessage(packet);

  } else if (packet.type === 'error') {
    // Ошибка от сервера
    addLog(`[ERR] Ошибка сервера: ${packet.error}`);
  }
}

// Отображение списка активных пользователей в боковой панели
function updateUsersList(text) {
  const el = document.getElementById("users_list");
  const match = text.match(/Пользователи онлайн:\s*(.+)/);
  if (match && match[1]) {
    const users = match[1].split(',').map(u => u.trim()).filter(Boolean);
    document.getElementById("onlineCount").textContent = users.length;
    el.innerHTML = users.map(u => `<div style="padding:2px 0; cursor:pointer;" onclick="document.getElementById('to').value='${u}'">• ${u}</div>`).join('');
  }
}

// Инициация отправки сообщения (с предварительным запросом ключа при необходимости)
async function sendMsg() {
  let to = document.getElementById("to").value.trim();
  let text = document.getElementById("text").value.trim();
  if (!to) {
    addLog("[ERR] Укажите получателя в поле To");
    return;
  }
  if (to.startsWith('@')) to = to.slice(1);
  if (!text) {
    addLog("[ERR] Введите текст сообщения");
    return;
  }

  if (!peerPublicKeys[to]) {
    if (!pendingMessages[to]) pendingMessages[to] = [];
    pendingMessages[to].push(text);
    addLog(`[CRYPTO] Запрос сертификата для '${to}'...`);
    sendPacket({ type: "key_request", to: to });
  } else {
    await sendEncryptedMessage(to, text);
  }
  document.getElementById("text").value = "";
}

// Сквозное (E2E) шифрование сообщения гибридной схемой RSA + AES-256-GCM
async function sendEncryptedMessage(to, text) {
  try {
    const peerKey = peerPublicKeys[to];
    if (!peerKey) throw new Error("Ключ получателя не найден");

    // 1. Генерация случайного одноразового 256-битного сессионного ключа AES
    const aesKey = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

    // 2. Шифрование текста сообщения алгоритмом AES-256-GCM (с 12-байтным nonce)
    const nonce = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedText = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      aesKey,
      new TextEncoder().encode(text)
    );

    // 3. Асимметричное шифрование сессионного AES-ключа открытым ключом получателя (RSA-OAEP SHA-256)
    const encryptedAesKey = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      peerKey,
      rawAesKey
    );

    // 4. Отправка зашифрованного пакета на сервер
    sendPacket({
      type: "message",
      to: to,
      text: bufToB64(encryptedText),
      enc_key: bufToB64(encryptedAesKey),
      nonce: bufToB64(nonce)
    });

    addLog(`[OUT] -> @${to}: ${text}`);
  } catch (e) {
    addLog(`[ERR] Ошибка шифрования для @${to}: ${e.message}`);
  }
}

// Расшифровка входящего E2E-сообщения
async function handleIncomingMessage(packet) {
  const fromUser = packet.from || packet.from_user || "?";
  try {
    if (!myDecryptKey) throw new Error("Локальный ключ расшифровки отсутствует");

    const encKeyBytes = b64ToBuf(packet.enc_key);
    const nonceBytes = b64ToBuf(packet.nonce);
    const encryptedTextBytes = b64ToBuf(packet.text);

    // 1. Расшифровка сессионного ключа AES своим закрытым ключом RSA-OAEP
    const rawAesKey = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      myDecryptKey,
      encKeyBytes
    );

    // 2. Импорт расшифрованного AES-ключа
    const aesKey = await window.crypto.subtle.importKey(
      "raw",
      rawAesKey,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    // 3. Расшифровка содержимого сообщения алгоритмом AES-GCM
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonceBytes },
      aesKey,
      encryptedTextBytes
    );

    const plaintext = new TextDecoder().decode(decrypted);
    addLog(`[IN] @${fromUser}: ${plaintext}`);
  } catch (e) {
    addLog(`[ERR] Не удалось расшифровать сообщение от @${fromUser}: ${e.message}`);
  }
}

// Экспорт сертификата и закрытого ключа в зашифрованный файл резервной копии (.enc)
async function exportCrt() {
  const nick = document.getElementById("nickname").value.trim() || myNickname;
  const pwd = document.getElementById("cert_password").value;
  if (!nick) {
    addLog("[ERR] Укажите никнейм для экспорта");
    return;
  }
  if (!pwd) {
    addLog("[ERR] Введите пароль для шифрования backup .enc");
    return;
  }
  const privKeyPem = localStorage.getItem(`sun_in_key_${nick}`);
  const certPem = localStorage.getItem(`sun_in_cert_${nick}`);
  if (!privKeyPem || !certPem) {
    addLog(`[ERR] Не найден сертификат для '${nick}'`);
    return;
  }

  try {
    const encoder = new TextEncoder();
    // Вычисление ключа шифрования из пароля (SHA-256 -> AES-256)
    const pwdHash = await window.crypto.subtle.digest("SHA-256", encoder.encode(pwd));
    const encKey = await window.crypto.subtle.importKey("raw", pwdHash, { name: "AES-GCM" }, false, ["encrypt"]);

    const certBytes = encoder.encode(certPem);
    const keyBytes = encoder.encode(privKeyPem);

    // Упаковка: 4 байта длины сертификата (big-endian) + тело сертификата + закрытый ключ
    const lenBytes = new Uint8Array(4);
    new DataView(lenBytes.buffer).setUint32(0, certBytes.length, false);

    const plaintext = concatBytes(lenBytes, certBytes, keyBytes);
    const nonce = window.crypto.getRandomValues(new Uint8Array(12));

    // Шифрование данных алгоритмом AES-256-GCM
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      encKey,
      plaintext
    );

    const payload = concatBytes(nonce, new Uint8Array(ciphertext));
    const b64 = bufToB64(payload);

    // Скачивание зашифрованного файла .enc в браузере
    const blob = new Blob([b64], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${nick}.enc`;
    a.click();
    URL.revokeObjectURL(url);
    addLog(`[OK] Сертификат и ключ экспортированы в ${nick}.enc`);
  } catch (e) {
    addLog(`[ERR] Ошибка экспорта: ${e.message}`);
  }
}

// Импорт сертификата и закрытого ключа из зашифрованного файла (.enc) в localStorage
function handleImportFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  const pwd = document.getElementById("cert_password").value;
  if (!pwd) {
    addLog("[ERR] Введите пароль для расшифровки .enc перед выбором файла");
    event.target.value = "";
    return;
  }
  const nick = document.getElementById("nickname").value.trim() || file.name.replace(/\.enc$/i, '');
  document.getElementById("nickname").value = nick;

  const reader = new FileReader();
  reader.onload = async function (e) {
    try {
      const b64 = e.target.result.trim();
      const raw = b64ToBuf(b64);
      const nonce = raw.slice(0, 12);
      const ciphertext = raw.slice(12);

      const encoder = new TextEncoder();
      const pwdHash = await window.crypto.subtle.digest("SHA-256", encoder.encode(pwd));
      const encKey = await window.crypto.subtle.importKey("raw", pwdHash, { name: "AES-GCM" }, false, ["decrypt"]);

      // Расшифровка файла с помощью пароля
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce },
        encKey,
        ciphertext
      );

      const decBytes = new Uint8Array(decrypted);
      const certLen = new DataView(decBytes.buffer).getUint32(0, false);
      const certBytes = decBytes.slice(4, 4 + certLen);
      const keyBytes = decBytes.slice(4 + certLen);

      const decoder = new TextDecoder();
      const certPem = decoder.decode(certBytes);
      const keyPem = decoder.decode(keyBytes);

      // Сохранение импортированных ключей в localStorage браузера
      localStorage.setItem(`sun_in_key_${nick}`, keyPem);
      localStorage.setItem(`sun_in_cert_${nick}`, certPem);
      addLog(`[OK] Сертификат и ключ для '${nick}' успешно импортированы! Нажмите Connect.`);
    } catch (err) {
      addLog(`[ERR] Ошибка импорта: ${err.message}`);
    }
    event.target.value = "";
  };
  reader.readAsText(file);
}

addLog("[INIT] Web Client готов (подключена библиотека x509).");
setStatus("DISCONNECTED", false);
