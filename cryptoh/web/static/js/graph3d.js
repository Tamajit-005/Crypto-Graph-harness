(function () {
  'use strict';

  let scene, camera, renderer;
  let nodeMeshes = {};
  let edgeLines = null;
  let frameId = null;
  let latestDot = '';
  let isDragging = false;
  let previousMouse = { x: 0, y: 0 };
  let spherical = { theta: Math.PI / 4, phi: Math.PI / 3, radius: 60 };
  let target = { x: 0, y: 0, z: 0 };

  function init() {
    const container = document.getElementById('graph3d');
    if (!container || typeof THREE === 'undefined') return;

    scene = new THREE.Scene();
    scene.background = new THREE.Color('#0d0d0d');

    camera = new THREE.PerspectiveCamera(55, container.clientWidth / Math.max(container.clientHeight, 1), 0.1, 1000);
    updateCameraFromSpherical();

    renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    const ambient = new THREE.AmbientLight('#ffffff', 0.7);
    scene.add(ambient);
    const dir = new THREE.DirectionalLight('#ffffff', 0.9);
    dir.position.set(10, 20, 10);
    scene.add(dir);

    renderer.domElement.addEventListener('mousedown', (e) => {
      isDragging = true;
      previousMouse.x = e.clientX;
      previousMouse.y = e.clientY;
    });
    window.addEventListener('mouseup', () => { isDragging = false; });
    window.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      const dx = e.clientX - previousMouse.x;
      const dy = e.clientY - previousMouse.y;
      spherical.theta -= dx * 0.01;
      spherical.phi = Math.max(0.2, Math.min(Math.PI - 0.2, spherical.phi - dy * 0.01));
      previousMouse.x = e.clientX;
      previousMouse.y = e.clientY;
      updateCameraFromSpherical();
    });
    renderer.domElement.addEventListener('wheel', (e) => {
      spherical.radius = Math.max(20, Math.min(200, spherical.radius + e.deltaY * 0.05));
      updateCameraFromSpherical();
      e.preventDefault();
    }, { passive: false });

    window.addEventListener('resize', onResize);
    tick();
  }

  function updateCameraFromSpherical() {
    if (!camera) return;
    const { theta, phi, radius } = spherical;
    camera.position.x = target.x + radius * Math.sin(phi) * Math.sin(theta);
    camera.position.y = target.y + radius * Math.cos(phi);
    camera.position.z = target.z + radius * Math.sin(phi) * Math.cos(theta);
    camera.lookAt(target.x, target.y, target.z);
  }

  function onResize() {
    const container = document.getElementById('graph3d');
    if (!container || !camera || !renderer) return;
    camera.aspect = container.clientWidth / Math.max(container.clientHeight, 1);
    camera.updateProjectionMatrix();
    renderer.setSize(container.clientWidth, container.clientHeight);
  }

  function tick() {
    frameId = requestAnimationFrame(tick);
    if (renderer && scene && camera) renderer.render(scene, camera);
  }

  function parseDot(dot) {
    const nodes = new Set();
    const edges = [];
    const re = /"([^"]+)"\s*->\s*"([^"]+)"/g;
    let m;
    while ((m = re.exec(dot)) !== null) {
      nodes.add(m[1]);
      nodes.add(m[2]);
      edges.push({ source: m[1], target: m[2] });
    }
    return { nodes: Array.from(nodes), edges };
  }

  function dispose(obj) {
    if (!obj) return;
    if (obj.geometry) obj.geometry.dispose();
    if (obj.material) {
      if (Array.isArray(obj.material)) obj.material.forEach((x) => x.dispose());
      else obj.material.dispose();
    }
  }

  function clear() {
    if (edgeLines) { scene.remove(edgeLines); dispose(edgeLines); edgeLines = null; }
    Object.values(nodeMeshes).forEach((obj) => { scene.remove(obj); dispose(obj); });
    nodeMeshes = {};
  }

  function build(dot, anomalousNodes) {
    if (!scene) return;
    clear();
    latestDot = dot || latestDot;
    const { nodes, edges } = parseDot(latestDot);
    const anom = new Set(anomalousNodes || []);
    const ids = nodes;

    const radius = 18;
    ids.forEach((id, idx) => {
      const phi = Math.acos(1 - 2 * (idx + 0.5) / Math.max(ids.length, 1));
      const theta = Math.PI * (1 + Math.sqrt(5)) * idx;
      const x = radius * Math.sin(phi) * Math.cos(theta);
      const y = radius * Math.sin(phi) * Math.sin(theta);
      const z = radius * Math.cos(phi);

      const geo = new THREE.SphereGeometry(0.7, 16, 16);
      const mat = new THREE.MeshStandardMaterial({
        color: anom.has(id) ? '#ff00ff' : '#00ffff',
        emissive: anom.has(id) ? '#330033' : '#003333',
      });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.set(x, y, z);
      scene.add(mesh);
      nodeMeshes[id] = mesh;
    });

    const lineGeo = new THREE.BufferGeometry();
    const positions = [];
    edges.forEach((e) => {
      const a = nodeMeshes[e.source];
      const b = nodeMeshes[e.target];
      if (!a || !b) return;
      positions.push(a.position.x, a.position.y, a.position.z);
      positions.push(b.position.x, b.position.y, b.position.z);
    });
    lineGeo.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    const lineMat = new THREE.LineBasicMaterial({
      color: '#555555',
      transparent: true,
      opacity: 0.4,
    });
    edgeLines = new THREE.LineSegments(lineGeo, lineMat);
    scene.add(edgeLines);
  }

  window.renderGraph3D = function (dot, anomalousNodes) {
    if (!scene) init();
    build(dot, anomalousNodes);
  };
})();
