fetch('/rest/v1/debug-sate')
        .then(response => response.json())
        .then(data => {
            if (data.debug) {
                var debugElement = document.getElementById('debug');
                debugElement.innerHTML = 'DEBUG-Modus';
                debugElement.className ='blink';
            }
        });