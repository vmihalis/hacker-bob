import { useEffect, useRef } from 'react';
import {
  AmbientLight,
  BufferAttribute,
  BufferGeometry,
  CanvasTexture,
  CatmullRomCurve3,
  Color,
  DodecahedronGeometry,
  Group,
  IcosahedronGeometry,
  Line,
  LineBasicMaterial,
  type Material,
  Mesh,
  MeshBasicMaterial,
  MeshStandardMaterial,
  type Object3D,
  PerspectiveCamera,
  PointLight,
  Points,
  PointsMaterial,
  Scene,
  SphereGeometry,
  Sprite,
  SpriteMaterial,
  SRGBColorSpace,
  Texture,
  TorusGeometry,
  Vector3,
  WebGLRenderer,
  type BufferGeometry as ThreeBufferGeometry,
} from 'three';

const stages = ['SURFACE_DISCOVERY', 'AUTH', 'EVALUATE', 'CHAIN', 'VERIFY', 'GRADE', 'REPORT'];

function createStageLabel(text: string, accent: string) {
  const canvas = document.createElement('canvas');
  canvas.width = 384;
  canvas.height = 128;

  const context = canvas.getContext('2d');
  if (!context) {
    return null;
  }

  context.clearRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = 'rgba(5, 8, 9, 0.72)';
  context.strokeStyle = 'rgba(140, 255, 99, 0.54)';
  context.lineWidth = 2;
  context.beginPath();
  context.roundRect(34, 28, 316, 68, 8);
  context.fill();
  context.stroke();

  context.font = '700 32px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
  context.fillStyle = accent;
  context.textAlign = 'center';
  context.textBaseline = 'middle';
  context.fillText(text, canvas.width / 2, 64);

  const texture = new CanvasTexture(canvas);
  texture.colorSpace = SRGBColorSpace;
  texture.needsUpdate = true;

  const material = new SpriteMaterial({
    map: texture,
    transparent: true,
    opacity: 0.92,
    depthWrite: false,
  });

  const sprite = new Sprite(material);
  sprite.scale.set(1.7, 0.56, 1);
  return sprite;
}

function disposeScene(scene: Scene, renderer: WebGLRenderer) {
  scene.traverse((child) => {
    const object = child as Object3D & {
      geometry?: ThreeBufferGeometry;
      material?: Material | Material[];
    };

    object.geometry?.dispose();

    const materials = Array.isArray(object.material)
      ? object.material
      : object.material
        ? [object.material]
        : [];

    for (const material of materials) {
      const maybeTextured = material as Material & {
        map?: Texture;
        alphaMap?: Texture;
      };
      maybeTextured.map?.dispose();
      maybeTextured.alphaMap?.dispose();
      material.dispose();
    }
  });

  renderer.dispose();
}

export default function HeroScene() {
  const mountRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) {
      return;
    }

    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const mobile = window.matchMedia('(max-width: 720px)').matches;

    const scene = new Scene();
    const renderer = new WebGLRenderer({
      alpha: true,
      antialias: !mobile,
      powerPreference: 'high-performance',
    });

    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, mobile ? 1.25 : 1.75));
    mount.appendChild(renderer.domElement);

    const camera = new PerspectiveCamera(44, 1, 0.1, 80);
    camera.position.set(0, 0, mobile ? 11.5 : 10);

    const ambient = new AmbientLight(0x6dff70, 0.32);
    const keyLight = new PointLight(0x8cff63, 12, 18);
    keyLight.position.set(-4.5, 4.2, 4);
    const rimLight = new PointLight(0xffffff, 3.8, 18);
    rimLight.position.set(4.8, -2.5, 4);
    scene.add(ambient, keyLight, rimLight);

    const pipeline = new Group();
    pipeline.position.y = mobile ? -1.1 : -0.45;
    scene.add(pipeline);

    const acid = '#8cff63';
    const warning = '#ff4d57';
    const steel = '#8aa0a8';
    const stageSpan = mobile ? 6.4 : 10.6;
    const positions = stages.map((stage, index) => {
      const x = -stageSpan / 2 + (stageSpan * index) / (stages.length - 1);
      const y = mobile ? Math.sin(index * 1.4) * 0.22 : Math.sin(index * 0.95) * 0.46;
      const z = Math.cos(index * 0.78) * (mobile ? 0.35 : 0.62);
      return { stage, position: new Vector3(x, y, z) };
    });

    const nodeGeometry = new IcosahedronGeometry(mobile ? 0.18 : 0.24, 1);
    const nodeMaterial = new MeshStandardMaterial({
      color: new Color(acid),
      emissive: new Color('#42ff54'),
      emissiveIntensity: 0.72,
      metalness: 0.2,
      roughness: 0.32,
    });
    const verifyMaterial = new MeshStandardMaterial({
      color: new Color('#ffffff'),
      emissive: new Color(acid),
      emissiveIntensity: 0.55,
      metalness: 0.14,
      roughness: 0.3,
    });

    const nodes: Mesh[] = [];
    positions.forEach(({ stage, position }, index) => {
      const mesh = new Mesh(
        nodeGeometry,
        stage === 'VERIFY' || stage === 'GRADE' ? verifyMaterial : nodeMaterial,
      );
      mesh.position.copy(position);
      mesh.userData.phase = index;
      pipeline.add(mesh);
      nodes.push(mesh);

      const ring = new Mesh(
        new TorusGeometry(mobile ? 0.28 : 0.38, 0.012, 8, 48),
        new MeshBasicMaterial({
          color: stage === 'REPORT' ? warning : acid,
          transparent: true,
          opacity: stage === 'REPORT' ? 0.52 : 0.36,
        }),
      );
      ring.position.copy(position);
      ring.rotation.x = Math.PI / 2;
      pipeline.add(ring);

      if (!mobile || index % 2 === 0) {
        const label = createStageLabel(stage, stage === 'REPORT' ? warning : acid);
        if (label) {
          label.position.copy(position.clone().add(new Vector3(0, mobile ? 0.58 : 0.76, 0)));
          pipeline.add(label);
        }
      }
    });

    const lineMaterial = new LineBasicMaterial({
      color: new Color('#8cff63'),
      transparent: true,
      opacity: 0.36,
    });
    for (let index = 0; index < positions.length - 1; index += 1) {
      const curve = new CatmullRomCurve3([
        positions[index].position,
        positions[index].position
          .clone()
          .lerp(positions[index + 1].position, 0.5)
          .add(new Vector3(0, index % 2 === 0 ? 0.34 : -0.28, 0.14)),
        positions[index + 1].position,
      ]);
      const geometry = new BufferGeometry().setFromPoints(curve.getPoints(28));
      pipeline.add(new Line(geometry, lineMaterial));
    }

    const core = new Group();
    core.position.set(0, mobile ? 1.3 : 1.55, -0.75);
    pipeline.add(core);

    const coreMesh = new Mesh(
      new DodecahedronGeometry(mobile ? 0.45 : 0.62, 0),
      new MeshStandardMaterial({
        color: new Color('#0e1718'),
        emissive: new Color('#8cff63'),
        emissiveIntensity: 0.36,
        metalness: 0.7,
        roughness: 0.18,
      }),
    );
    core.add(coreMesh);

    const coreWire = new Mesh(
      new DodecahedronGeometry(mobile ? 0.52 : 0.72, 0),
      new MeshBasicMaterial({
        color: new Color('#ffffff'),
        wireframe: true,
        transparent: true,
        opacity: 0.18,
      }),
    );
    core.add(coreWire);

    if (!mobile) {
      const coreLabel = createStageLabel('MCP STATE', steel);
      if (coreLabel) {
        coreLabel.position.set(0, 0.95, 0);
        core.add(coreLabel);
      }
    }

    const coreLineMaterial = new LineBasicMaterial({
      color: new Color('#5f7480'),
      transparent: true,
      opacity: mobile ? 0.11 : 0.16,
    });
    for (const { position } of positions) {
      const geometry = new BufferGeometry().setFromPoints([core.position, position]);
      pipeline.add(new Line(geometry, coreLineMaterial));
    }

    const pulseGeometry = new SphereGeometry(mobile ? 0.045 : 0.06, 12, 12);
    const pulseMaterial = new MeshBasicMaterial({
      color: new Color('#ffffff'),
      transparent: true,
      opacity: 0.92,
    });
    const pulseCount = mobile ? 3 : 7;
    const pulses = Array.from({ length: pulseCount }, (_, index) => {
      const pulse = new Mesh(pulseGeometry, pulseMaterial);
      pulse.userData.offset = index / pulseCount;
      pipeline.add(pulse);
      return pulse;
    });

    const particleCount = mobile ? 90 : 240;
    const particlePositions = new Float32Array(particleCount * 3);
    for (let index = 0; index < particleCount; index += 1) {
      particlePositions[index * 3] = (Math.random() - 0.5) * (mobile ? 9 : 15);
      particlePositions[index * 3 + 1] = (Math.random() - 0.5) * (mobile ? 7 : 8);
      particlePositions[index * 3 + 2] = (Math.random() - 0.5) * 6;
    }
    const particleGeometry = new BufferGeometry();
    particleGeometry.setAttribute('position', new BufferAttribute(particlePositions, 3));
    const particles = new Points(
      particleGeometry,
      new PointsMaterial({
        color: new Color('#8aa0a8'),
        size: mobile ? 0.018 : 0.024,
        transparent: true,
        opacity: mobile ? 0.3 : 0.44,
        depthWrite: false,
      }),
    );
    scene.add(particles);

    const resize = () => {
      const width = mount.clientWidth || window.innerWidth;
      const height = mount.clientHeight || window.innerHeight;
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
    };

    let animationFrame = 0;
    const render = (time = 0) => {
      const seconds = time * 0.001;

      pipeline.rotation.y = Math.sin(seconds * 0.23) * (mobile ? 0.08 : 0.15);
      pipeline.rotation.x = Math.sin(seconds * 0.17) * 0.05;
      coreMesh.rotation.x = seconds * 0.26;
      coreMesh.rotation.y = seconds * 0.38;
      coreWire.rotation.y = -seconds * 0.16;

      nodes.forEach((node, index) => {
        const scale = 1 + Math.sin(seconds * 2.2 + index) * 0.08;
        node.scale.setScalar(scale);
        node.rotation.x = seconds * 0.42 + index;
        node.rotation.y = seconds * 0.35 - index * 0.4;
      });

      pulses.forEach((pulse) => {
        const progress = (seconds * 0.12 + pulse.userData.offset) % 1;
        const scaled = progress * (positions.length - 1);
        const segment = Math.min(Math.floor(scaled), positions.length - 2);
        const local = scaled - segment;
        const start = positions[segment].position;
        const end = positions[segment + 1].position;
        pulse.position.copy(start).lerp(end, local);
        pulse.position.y += Math.sin(local * Math.PI) * 0.22;
      });

      particles.rotation.z = seconds * 0.018;
      particles.rotation.y = Math.sin(seconds * 0.08) * 0.08;

      renderer.render(scene, camera);

      if (!reducedMotion) {
        animationFrame = window.requestAnimationFrame(render);
      }
    };

    resize();
    render();

    window.addEventListener('resize', resize);

    return () => {
      window.removeEventListener('resize', resize);
      if (animationFrame) {
        window.cancelAnimationFrame(animationFrame);
      }
      mount.removeChild(renderer.domElement);
      disposeScene(scene, renderer);
    };
  }, []);

  return <div ref={mountRef} className="hero-scene" aria-hidden="true" />;
}
