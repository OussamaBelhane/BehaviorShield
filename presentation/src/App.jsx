import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ChevronRight, 
  ChevronLeft, 
  Skull, 
  Eye, 
  Crosshair, 
  Zap, 
  Database,
  Swords,
  Crown
} from 'lucide-react';

const slides = [
  // Slide 1: Title - The Hook
  (props) => (
    <div className={`slide ${props.className}`}>
      <div className="power-container">
        <div className="logo-icon pulse-red" style={{ margin: '0 auto 2rem auto', width: '120px', height: '120px', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
          <Shield size={64} color="#fff" />
        </div>
        <h1 className="glitch-text" data-text="L'ILLUSION DE LA SÉCURITÉ">L'ILLUSION DE LA SÉCURITÉ</h1>
        <p className="subtitle">
          Le monde confie ses données à des antivirus obsolètes. <br/>
          Il est temps d'imposer un contrôle absolu.
        </p>
        <div className="glass-card minimal-card">
          <h2 style={{ fontSize: '2rem', color: 'var(--accent-red)', margin: 0, fontWeight: 800 }}>BEHAVIORSHIELD</h2>
          <p style={{ margin: 0, marginTop: '0.5rem', color: '#000', fontWeight: 600 }}>Projet de Fin d'Année — L'Arme Ultime contre les Ransomwares</p>
        </div>
      </div>
    </div>
  ),

  // Slide 2: Problématique
  (props) => (
    <div className={`slide ${props.className}`}>
      <div className="badge danger">LOI 1 : CONNAÎTRE SON ENNEMI</div>
      <h2 className="title-massive">L'ENNEMI EST <span className="highlight-red">INVISIBLE</span></h2>
      
      <div className="grid-2 align-center">
        <div>
          <p className="statement">
            Un ransomware ne négocie pas. Il frappe au cœur de votre système, chiffre vos années de travail en quelques secondes et exige une rançon.
          </p>
          <div className="power-list">
            <div className="power-item">
              <Skull size={32} color="var(--accent-red)" />
              <div><strong>Vitesse impitoyable :</strong> 14 secondes pour paralyser un réseau.</div>
            </div>
            <div className="power-item">
              <Eye size={32} color="var(--accent-red)" />
              <div><strong>Polymorphisme :</strong> Il change de visage à chaque attaque.</div>
            </div>
          </div>
        </div>
        
        <div className="visual-block danger-block">
          <div className="giant-icon"><Skull size={100} color="var(--accent-red)" /></div>
          <h3 style={{ color: '#000', fontSize: '2rem', textAlign: 'center', fontWeight: 800, marginTop: '1rem' }}>Dommages Mondiaux</h3>
          <div className="stat-number" style={{ textAlign: 'center' }}>20 Milliards $</div>
        </div>
      </div>
    </div>
  ),

  // Slide 3: The Gap
  (props) => (
    <div className={`slide ${props.className}`}>
      <div className="badge danger">LOI 2 : EXPLOITER LA FAIBLESSE</div>
      <h2 className="title-massive">LA FAILLE <span className="highlight-red">FATALE</span> DES ANTIVIRUS</h2>
      
      <p className="statement centered">
        Les antivirus traditionnels sont réactifs. Ils attendent qu'un malware soit connu (signature) pour le bloquer. 
        Face à une arme <strong>Zero-Day</strong> (inconnue), ils sont aveugles.
      </p>

      <div className="grid-2" style={{ marginTop: '3rem' }}>
        <div className="glass-card strike-card">
          <h3 style={{ color: '#000', textDecoration: 'line-through', fontWeight: 800 }}>La Méthode Faible</h3>
          <p style={{ color: '#444', fontWeight: 600 }}>Comparer le fichier à une liste noire. Si le fichier vient d'être créé, la liste est vide. Le système est détruit.</p>
        </div>
        <div className="glass-card power-card">
          <h3 style={{ color: 'var(--accent-blue)', fontWeight: 800 }}>La Méthode Implacable</h3>
          <p style={{ color: '#000', fontWeight: 600 }}>Ne jugez pas un fichier par ce qu'il prétend être. Jugez-le par ses actes. <strong>Le comportement ne ment jamais.</strong></p>
        </div>
      </div>
    </div>
  ),

  // Slide 4: The Solution
  (props) => (
    <div className={`slide ${props.className}`}>
      <div className="badge">LOI 3 : FRAPPER AVEC FORCE</div>
      <h2 className="title-massive">LE <span className="highlight-blue">PRÉDATEUR</span> : BEHAVIORSHIELD</h2>
      <p className="statement">
        Nous n'attendons pas la signature. Nous observons le comportement. Dès qu'un processus tente un chiffrement de masse, <strong>nous l'exécutons sans pitié.</strong>
      </p>

      <div className="grid-3 stats-grid">
        <div className="stat-box">
          <Eye size={40} color="#000" />
          <h3>Surveillance Absolue</h3>
          <p>Sysmon capture chaque souffle du noyau Windows. Rien n'échappe à notre regard.</p>
        </div>
        <div className="stat-box active">
          <Crosshair size={40} color="var(--accent-red)" />
          <h3>Jugement</h3>
          <p>Un algorithme attribue des points de menace. À 100 points, la sentence est prononcée.</p>
        </div>
        <div className="stat-box">
          <Zap size={40} color="#000" />
          <h3>Exécution</h3>
          <p>Le processus est assassiné. Le fichier est mis en quarantaine. L'ordinateur survit.</p>
        </div>
      </div>
    </div>
  ),

  // Slide 5: Architecture
  (props) => (
    <div className={`slide ${props.className}`}>
      <div className="badge">LOI 4 : CONSTRUIRE SA FORTERESSE</div>
      <h2 className="title-massive">L'ARCHITECTURE DU <span className="highlight-purple">POUVOIR</span></h2>
      
      <div className="architecture-diagram">
        <div className="node kernel">
          <Database size={32} color="#000" />
          <span>LE NOYAU (SYSMON)</span>
          <small>La source de la vérité absolue</small>
        </div>
        <div className="connector"></div>
        <div className="node engine">
          <Swords size={32} color="var(--accent-red)" />
          <span>LE MOTEUR (PYTHON)</span>
          <small>Le cerveau tactique et le bourreau</small>
        </div>
        <div className="connector"></div>
        <div className="node dashboard">
          <Crown size={32} color="#000" />
          <span>LE TRÔNE (REACT)</span>
          <small>Le contrôle visuel en temps réel</small>
        </div>
      </div>
    </div>
  ),

  // Slide 6: Live Demo
  (props) => (
    <div className={`slide ${props.className}`}>
      <div className="power-container demo-container">
        <div className="pulse-target" style={{ marginBottom: '2rem' }}>
          <Crosshair size={120} color="var(--accent-red)" />
        </div>
        <h2 className="title-massive">LE <span className="highlight-red">JUGEMENT</span> EN DIRECT</h2>
        <p className="statement centered">
          La théorie ne vaut rien sans la preuve du sang. <br/>
          Observez l'antivirus Premium s'effondrer. Observez BehaviorShield anéantir la menace.
        </p>
        <div className="play-button-wrapper">
           PASSER SUR LA MACHINE VIRTUELLE
        </div>
      </div>
    </div>
  ),

  // Slide 7: Metrics
  (props) => (
    <div className={`slide ${props.className}`}>
      <div className="badge">LOI 5 : LES RÉSULTATS SONT SOUVERAINS</div>
      <h2 className="title-massive">DOMINATION <span className="highlight-blue">STATISTIQUE</span></h2>
      
      <div className="grid-2">
        <div className="impact-card">
          <div className="impact-number">0.8<small>s</small></div>
          <h3>Temps d'exécution</h3>
          <p>Pour détecter et tuer un ransomware Zero-Day compilé en C Natif.</p>
        </div>
        <div className="impact-card">
          <div className="impact-number">0<small>%</small></div>
          <h3>Faux Positifs</h3>
          <p>L'OS respire. Aucun processus légitime (signé) n'a été touché.</p>
        </div>
      </div>
    </div>
  ),

  // Slide 8: Management
  (props) => (
    <div className={`slide ${props.className}`}>
      <div className="badge">LOI 6 : PLANIFIER JUSQU'À LA FIN</div>
      <h2 className="title-massive">LA <span className="highlight-purple">STRATÉGIE</span></h2>
      <p className="statement">Un empire ne se bâtit pas au hasard. Chaque ligne de code fut planifiée.</p>
      
      <div className="grid-2 align-center">
        <div className="visual-list">
          <div className="list-row">
            <span className="bullet">01</span>
            <div><strong>Scrum Hybride :</strong> 4 Sprints d'exécution impitoyable. Validation continue.</div>
          </div>
          <div className="list-row">
            <span className="bullet">02</span>
            <div><strong>Diagramme de Gantt :</strong> Parallélisation du noyau et de l'interface visuelle.</div>
          </div>
          <div className="list-row">
            <span className="bullet">03</span>
            <div><strong>Réseau PERT :</strong> Priorisation du chemin critique (L'interception avant le scoring).</div>
          </div>
        </div>
      </div>
    </div>
  ),

  // Slide 9: Entrepreneurship (BMC)
  (props) => (
    <div className={`slide ${props.className}`}>
      <div className="badge">LOI 7 : MONOPOLISER LA VALEUR</div>
      <h2 className="title-massive">CONQUÊTE DU <span className="highlight-green">MARCHÉ</span> (BMC)</h2>
      
      <div className="grid-3 power-bmc">
        <div className="bmc-block">
          <h3>La Cible</h3>
          <p>PME, TPE médicales, Cabinets comptables. Ceux qui possèdent des données vitales mais n'ont pas les moyens de payer un EDR Enterprise.</p>
        </div>
        <div className="bmc-block dominant">
          <h3>L'Arme (Valeur)</h3>
          <p>Une protection comportementale de grade militaire, accessible instantanément. Comble la faille des antivirus classiques.</p>
        </div>
        <div className="bmc-block">
          <h3>Le Tribut (Revenus)</h3>
          <p><strong>Freemium Absolu :</strong> Gratuit en local (Community) pour tuer la concurrence. 350 MAD/poste/an pour la domination centralisée (Professional).</p>
        </div>
      </div>
    </div>
  ),

  // Slide 10: Conclusion
  (props) => (
    <div className={`slide ${props.className}`}>
      <div className="power-container">
        <div className="logo-icon" style={{ margin: '0 auto 2rem auto', width: '100px', height: '100px', background: 'var(--accent-blue)', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
          <Crown size={50} color="#fff" />
        </div>
        <h2 className="title-massive" style={{ textAlign: 'center' }}>LE POUVOIR EST <span className="highlight-blue">VOTRE</span></h2>
        <p className="statement centered" style={{ fontSize: '1.6rem', maxWidth: '800px', margin: '0 auto' }}>
          La cybersécurité n'est pas un jeu défensif. C'est une guerre de contrôle. <br/><br/>
          Avec <strong>BehaviorShield</strong>, nous ne subissons plus la menace, nous la neutralisons avant même qu'elle ne comprenne ce qui l'a frappée.
        </p>
        <h3 style={{ marginTop: '4rem', color: '#000', fontWeight: 800, fontSize: '2rem' }}>La présentation est terminée.</h3>
        <p style={{ color: 'var(--accent-red)', fontWeight: 800, fontSize: '1.5rem', marginTop: '1rem' }}>Des questions ?</p>
      </div>
    </div>
  )
];

function App() {
  const [currentSlide, setCurrentSlide] = useState(0);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'ArrowRight' || e.key === ' ') {
        setCurrentSlide(prev => Math.min(prev + 1, slides.length - 1));
      } else if (e.key === 'ArrowLeft') {
        setCurrentSlide(prev => Math.max(prev - 1, 0));
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const nextSlide = () => setCurrentSlide(prev => Math.min(prev + 1, slides.length - 1));
  const prevSlide = () => setCurrentSlide(prev => Math.max(prev - 1, 0));

  return (
    <div className="presentation-container power-theme">
      <div className="grid-overlay"></div>
      <div className="vignette"></div>

      <div className="slide-content">
        {slides.map((SlideComponent, index) => {
          let className = '';
          if (index === currentSlide) className = 'active';
          else if (index < currentSlide) className = 'prev';
          
          return <SlideComponent key={index} className={className} />;
        })}
      </div>

      <div className="controls">
        <button className="control-btn" onClick={prevSlide} disabled={currentSlide === 0}>
          <ChevronLeft size={24} />
        </button>
        <div className="progress-bar">
          <div className="progress-fill" style={{ width: `${((currentSlide + 1) / slides.length) * 100}%` }}></div>
        </div>
        <button className="control-btn" onClick={nextSlide} disabled={currentSlide === slides.length - 1}>
          <ChevronRight size={24} />
        </button>
      </div>
    </div>
  );
}

export default App;
