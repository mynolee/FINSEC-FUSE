import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { FuseApi } from './api';
import { Icon } from './components/ui';
import { WorkflowPage } from './components/Workflows';
import { QuarantinePage } from './components/Quarantine';
import { ExperimentsPage } from './components/Experiments';

export type Route = { page: 'workflows' | 'quarantine' | 'experiments'; id?: string };
export function readRoute(): Route {
  const [page, id] = window.location.hash.replace(/^#\/?/, '').split('/');
  return {
    page: page === 'quarantine' || page === 'experiments' ? page : 'workflows',
    ...(id
      ? {
          id: (() => {
            try {
              return decodeURIComponent(id);
            } catch {
              return 'invalid-route';
            }
          })(),
        }
      : {}),
  };
}
export function navigate(page: Route['page'], id?: string) {
  window.location.hash = `/${page}${id ? `/${encodeURIComponent(id)}` : ''}`;
}
export default function App() {
  const [token, setToken] = useState('');
  const [inputToken, setInputToken] = useState('');
  const [route, setRoute] = useState(readRoute);
  const api = useMemo(() => new FuseApi(token), [token]);
  useEffect(() => {
    const change = () => setRoute(readRoute());
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);
  useEffect(() => {
    // A restored back-forward cache must not resurrect a previous operator session.
    const clearSession = () => {
      setToken('');
      setInputToken('');
    };
    const restore = (event: PageTransitionEvent) => {
      if (event.persisted) clearSession();
    };
    window.addEventListener('pagehide', clearSession);
    window.addEventListener('pageshow', restore);
    return () => {
      window.removeEventListener('pagehide', clearSession);
      window.removeEventListener('pageshow', restore);
    };
  }, []);
  function connect(event: FormEvent) {
    event.preventDefault();
    const next = inputToken.trim();
    if (next) {
      setToken(next);
      setInputToken('');
    }
  }
  const nav = [
    {
      page: 'workflows' as const,
      name: '업무 모니터',
      icon: 'grid' as const,
      subtitle: 'Workflow operations',
    },
    {
      page: 'quarantine' as const,
      name: '격리 · 영향 조사',
      icon: 'shield' as const,
      subtitle: 'Containment & recovery',
    },
    { page: 'experiments' as const, name: '비교 실험', icon: 'flask' as const, subtitle: 'Baseline / FUSE' },
  ];
  return (
    <div className="app-shell">
      <a
        href="#main"
        className="skip-link"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById('main')?.focus();
        }}
      >
        본문으로 이동
      </a>
      <aside className="sidebar">
        <a className="brand" href="#/workflows" aria-label="FINSEC FUSE 업무 모니터">
          <span className="brand-mark">
            <Icon name="shield" size={25} />
          </span>
          <span>
            FINSEC <b>FUSE</b>
            <small>금융 AI 안전 제어</small>
          </span>
        </a>
        <div className="workspace-label">OPERATOR WORKSPACE</div>
        <nav aria-label="주 메뉴">
          {nav.map((item) => (
            <a
              href={`#/${item.page}`}
              key={item.page}
              className={`nav-item ${route.page === item.page ? 'active' : ''}`}
              aria-current={route.page === item.page ? 'page' : undefined}
            >
              <Icon name={item.icon} />
              <span>
                {item.name}
                <small>{item.subtitle}</small>
              </span>
              {route.page === item.page && <span className="nav-marker" />}
            </a>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="boundary-mark">
            <Icon name="lock" />
            <span>
              중앙 정책 경계<small>Browser → Spring → KYC</small>
            </span>
          </div>
          <p>
            Mock 금융 업무 전용
            <br />
            실은행 지급 기능은 없습니다.
          </p>
          <div className="version">
            FUSE–MVP–1 <span>DEMO</span>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            보안 운영 콘솔 <span>/</span>{' '}
            <strong>{nav.find((item) => item.page === route.page)?.name}</strong>
          </div>
          <div className="session-state">
            <span className={`connection-dot ${token ? 'connected' : ''}`} />
            {token ? '인증 토큰 입력됨' : '연결 전'}
            {token && (
              <button
                className="text-button"
                onClick={() => {
                  setToken('');
                  navigate('workflows');
                }}
              >
                연결 해제
              </button>
            )}
          </div>
        </header>
        <main id="main" tabIndex={-1} key={token ? 'connected' : 'disconnected'}>
          {!token ? (
            <div className="welcome">
              <div className="welcome-copy">
                <span className="eyebrow">TRUST IS VERIFIED, NOT ASSUMED</span>
                <h1>
                  판단이 지급으로 이어지기 전,
                  <br />
                  <em>한 번 더 확인합니다.</em>
                </h1>
                <p>
                  신원 확인부터 지급까지, 증거와 권한의 연결을 살펴보세요. 관계있는 실행만 멈추고 독립된 정상
                  업무는 계속합니다.
                </p>
                <div className="welcome-steps">
                  <span>01 독립 증거</span>
                  <span>02 정확한 승인</span>
                  <span>03 선택적 격리</span>
                </div>
              </div>
              <section className="connect-card">
                <span className="connect-icon">
                  <Icon name="lock" size={26} />
                </span>
                <h2>운영 콘솔 연결</h2>
                <p>개발 환경에서 발급한 역할별 토큰을 입력하세요. 서버가 실제 주체와 권한을 확인합니다.</p>
                <form onSubmit={connect}>
                  <label htmlFor="token">개발용 인증 토큰</label>
                  <input
                    id="token"
                    type="password"
                    value={inputToken}
                    onChange={(e) => setInputToken(e.target.value)}
                    autoComplete="off"
                    placeholder="Bearer를 제외한 토큰"
                    required
                    spellCheck={false}
                  />
                  <button className="button primary full" type="submit">
                    연결하고 업무 조회 <Icon name="arrow" size={18} />
                  </button>
                </form>
                <small>
                  토큰은 이 화면의 메모리에만 보관해요. 새로고침하거나 연결을 해제하면 사라집니다.
                </small>
              </section>
              <div className="welcome-note">
                <span className="status neutral">LOCAL DEVELOPMENT</span>
                <p>
                  화면은 Spring API가 반환한 기록만 표시해요. 연결 전에는 업무 수나 지급 성공을 표시하지
                  않습니다.
                </p>
              </div>
            </div>
          ) : (
            <>
              {route.page === 'workflows' && <WorkflowPage api={api} id={route.id} />}
              {route.page === 'quarantine' && (
                <QuarantinePage key={route.id || 'quarantine'} api={api} id={route.id} />
              )}
              {route.page === 'experiments' && (
                <ExperimentsPage key={route.id || 'experiments'} api={api} id={route.id} />
              )}
            </>
          )}
        </main>
        <footer className="page-footer">
          <span>FINSEC FUSE</span>
          <p>위험 점수는 금액이나 확률이 아닙니다. · 모든 시간은 UTC</p>
          <span>정책과 출처를 함께 확인하세요</span>
        </footer>
      </div>
    </div>
  );
}
