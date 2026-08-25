const header = document.querySelector('.site-header');
const menuToggle = document.querySelector('.menu-toggle');

menuToggle?.addEventListener('click', () => {
  const open = header.classList.toggle('menu-open');
  menuToggle.setAttribute('aria-expanded', String(open));
  menuToggle.textContent = open ? '×' : '☰';
});

document.querySelectorAll('.desktop-nav a').forEach(link => {
  link.addEventListener('click', () => {
    header.classList.remove('menu-open');
    menuToggle?.setAttribute('aria-expanded', 'false');
    if (menuToggle) menuToggle.textContent = '☰';
  });
});

const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.12 });

document.querySelectorAll('.reveal').forEach(el => observer.observe(el));

const hero = document.querySelector('.hero');
if (hero && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
  hero.addEventListener('pointermove', e => {
    const visual = document.querySelector('.hero-visual .visual-main');
    if (!visual) return;
    const x = (e.clientX / window.innerWidth - .5) * 6;
    const y = (e.clientY / window.innerHeight - .5) * -6;
    visual.style.transform = `rotate(${2 + x / 8}deg) translate(${x}px, ${y}px)`;
  });
  hero.addEventListener('pointerleave', () => {
    const visual = document.querySelector('.hero-visual .visual-main');
    if (visual) visual.style.transform = '';
  });
}
