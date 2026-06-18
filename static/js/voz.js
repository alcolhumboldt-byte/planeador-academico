/**
 * Planeador Académico — Reconocimiento de voz
 * Funciona en Chrome (desktop, iPad, tablet Android)
 * Sin instalación — usa la API nativa del navegador
 */

const Voz = {
  reconocedor: null,
  grabando:    false,
  idioma:      'es-CO',  // Español colombiano

  // Verifica si el navegador soporta reconocimiento de voz
  disponible() {
    return 'webkitSpeechRecognition' in window || 'SpeechRecognition' in window;
  },

  // Inicializa el reconocedor
  init() {
    if (!this.disponible()) return false;
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    this.reconocedor = new SR();
    this.reconocedor.lang           = this.idioma;
    this.reconocedor.continuous     = false;  // Para cuando deja de hablar
    this.reconocedor.interimResults = true;   // Mostrar texto mientras habla
    return true;
  },

  /**
   * Inicia grabación y llena un campo de texto.
   * @param {string}   inputId   — ID del <input> o <textarea> a llenar
   * @param {string}   btnId     — ID del botón de micrófono
   * @param {string}   estadoId  — ID del elemento de estado (opcional)
   * @param {function} onFin     — callback cuando termina (recibe el texto)
   */
  grabar(inputId, btnId, estadoId = null, onFin = null) {
    if (!this.reconocedor && !this.init()) {
      alert('Tu navegador no soporta reconocimiento de voz. Usa Chrome.');
      return;
    }

    if (this.grabando) {
      this.reconocedor.stop();
      return;
    }

    const input  = document.getElementById(inputId);
    const btn    = document.getElementById(btnId);
    const estado = estadoId ? document.getElementById(estadoId) : null;

    if (!input || !btn) return;

    const textoOriginal = input.value;
    this.grabando = true;
    btn.classList.add('grabando');
    btn.title = 'Toca para detener';
    if (estado) { estado.textContent = '🎤 Escuchando...'; estado.classList.add('visible'); }

    this.reconocedor.onresult = (e) => {
      let transcripcion = '';
      for (let i = e.resultIndex; i < e.results.length; i++) {
        transcripcion += e.results[i][0].transcript;
      }
      // Mostrar texto mientras habla (resultado parcial)
      input.value = textoOriginal
        ? textoOriginal + ' ' + transcripcion
        : transcripcion;
    };

    this.reconocedor.onerror = (e) => {
      this._detener(btn, estado);
      if (e.error === 'not-allowed') {
        alert('Permiso de micrófono denegado. Permite el acceso en la configuración del navegador.');
      } else if (e.error === 'no-speech') {
        if (estado) estado.textContent = 'No se detectó voz — intenta de nuevo';
      }
    };

    this.reconocedor.onend = () => {
      this._detener(btn, estado);
      if (onFin) onFin(input.value);
    };

    this.reconocedor.start();
  },

  _detener(btn, estado) {
    this.grabando = false;
    if (btn) { btn.classList.remove('grabando'); btn.title = 'Dictar'; }
    if (estado) { estado.textContent = ''; estado.classList.remove('visible'); }
  },

  /**
   * Crea un botón de micrófono y lo inserta al lado de un input.
   * @param {string} inputId  — ID del input a conectar
   * @param {function} onFin  — callback al terminar
   */
  crearBoton(inputId, onFin = null) {
    const btnId    = `mic-${inputId}`;
    const estadoId = `mic-estado-${inputId}`;

    const btn = document.createElement('button');
    btn.type      = 'button';
    btn.id        = btnId;
    btn.className = 'mic-btn';
    btn.title     = 'Dictar';
    btn.textContent = '🎤';
    btn.onclick = () => Voz.grabar(inputId, btnId, estadoId, onFin);

    const estadoDiv = document.createElement('div');
    estadoDiv.id        = estadoId;
    estadoDiv.className = 'mic-estado';

    return { btn, estadoDiv };
  },
};
