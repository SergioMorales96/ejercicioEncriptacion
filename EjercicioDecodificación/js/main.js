let numero = '0';
let arreglo = [];
let numerox = 0;

const mensaje = document.querySelector('#mensaje');
const mensajeDec = document.querySelector('#mensajeDec');

function ingresar() {
    numero = prompt('Ingrese la cantidad de filas:');
    numerox = parseFloat(numero);
    if (numerox >= 0) {
        pedirTexto();
    }
    else {
        ingresar();
    }
    this.transponer(arreglo);
    console.log(arreglo);
}

function pedirTexto() {
    let mensajeEncriptado = '';
    for (let i = 0; i < numerox; i++) {
        let fila = i + 1;
        let renglon = prompt('Ingrese la fila ' + fila + ':');
        let cadena = renglon.split('')
        arreglo.push(cadena);
        mensajeEncriptado = mensajeEncriptado.concat(renglon);
    }
    mensaje.innerHTML = mensajeEncriptado;
}

function transponer(matrizFilas) {
    let matrizColumnas = [];
    let mensajeTranspuesto = '';
    for (let i = 0; i < matrizFilas[0].length; i++) {
        let columna = [];
        for (let j = 0; j < matrizFilas.length; j++) {
            columna.push(matrizFilas[j][i]);
        }
        matrizColumnas.push(columna);
    }
    console.log(matrizColumnas);
    matrizColumnas.forEach(col => {
        for(let y = 0; y<col.length; y++) {
            mensajeTranspuesto = mensajeTranspuesto.concat(col[y]);
        }
    });
    console.log(mensajeTranspuesto);
    this.decodificarCesar(mensajeTranspuesto,3)
}

function decodificarCesar(cadena, desplazamiento) {
    let resultado = "";
    for (let i = 0; i < cadena.length; i++) {
        let char = cadena[i];
        
        if (char.match(/[a-z]/i)) {
            let isUpper = char === char.toUpperCase();
            char = char.toLowerCase();
            
            let code = char.charCodeAt(0);
            let decodedCode = ((code - 97 - desplazamiento + 26) % 26) + 97;
            
            if (isUpper) {
                resultado += String.fromCharCode(decodedCode).toUpperCase();
            } else {
                resultado += String.fromCharCode(decodedCode);
            }
        } else {
            resultado += char;
        }
    }
    console.log(resultado);
    mensajeDec.innerHTML = resultado;
    return resultado;
}
