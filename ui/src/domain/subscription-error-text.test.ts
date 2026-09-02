import { describe, expect, it } from 'vitest';
import { subscriptionErrorDetail } from './subscription-error-text';

const t = (key: string, options?: Record<string, string | number>) =>
  options ? `${key}:${String(options.status ?? '')}` : key;

describe('subscriptionErrorDetail', () => {
  it('已知分类优先走 i18n，HTTP 状态码随详情插值', () => {
    expect(
      subscriptionErrorDetail(
        { errorKind: 'http', httpStatus: 403, error: 'backend diagnostic' },
        t
      )
    ).toBe('sub.preview.httpDetail:403');
    expect(
      subscriptionErrorDetail({ errorKind: 'dns', error: 'backend diagnostic' }, t)
    ).toBe('sub.preview.dnsDetail:');
  });

  it('unknown 与旧载荷也不得把诊断直出到用户界面', () => {
    expect(
      subscriptionErrorDetail({ errorKind: 'unknown', error: 'tls handshake failed' }, t)
    ).toBe('sub.preview.unknownDetail:');
    expect(subscriptionErrorDetail({ message: 'legacy sanitized detail' }, t)).toBe('nodes.subRefreshFail');
  });

  it('没有分类也没有诊断时才落调用方 i18n 兜底', () => {
    expect(subscriptionErrorDetail({}, t, 'sub.previewFail')).toBe('sub.previewFail');
  });
});
