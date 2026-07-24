import { escapeHtml, RenderError, renderDocument } from '../src/renderer';
import { parseTemplateSource } from '../src/template-model';
import { sampleSource, sampleVariables } from './support';

const template = parseTemplateSource(sampleSource());

describe('renderDocument', () => {
  it('renders deterministically: same inputs, same bytes', () => {
    const a = renderDocument(template, sampleVariables());
    const b = renderDocument(template, sampleVariables());
    expect(a).toBe(b);
    expect(a).toContain('<!doctype html>');
    expect(a).toContain('<h1>Last Will and Testament</h1>');
    expect(a).toContain('I appoint Jordan Executor as executor.');
    expect(a).toContain('data-doc-type="will"');
  });

  it('includes and excludes clauses by boolean condition (with negation)', () => {
    const without = renderDocument(template, sampleVariables());
    expect(without).not.toContain('Guardianship');
    expect(without).toContain('I have no minor children.');

    const withKids = renderDocument(template, {
      ...sampleVariables(),
      hasMinorChildren: true,
      guardianName: 'Grace Guardian',
    });
    expect(withKids).toContain('I nominate Grace Guardian as guardian.');
    expect(withKids).not.toContain('I have no minor children.');
  });

  it('escapes every substituted value — intake data can never become markup', () => {
    const html = renderDocument(template, {
      ...sampleVariables(),
      testatorName: `<script>alert('x')</script>&"'`,
    });
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&quot;&#39;');
  });

  it('fails closed when an included clause references an absent optional value', () => {
    expect(() =>
      renderDocument(template, { ...sampleVariables(), hasMinorChildren: true }),
    ).toThrow(RenderError);
  });

  it('splits blank-line-separated text into paragraphs', () => {
    const source = parseTemplateSource(
      sampleSource({
        variables: [],
        body: [{ text: 'First paragraph.\n\nSecond paragraph.' }],
      }),
    );
    const html = renderDocument(source, {});
    expect(html).toContain('<p>First paragraph.</p>\n<p>Second paragraph.</p>');
  });

  it('refuses to render an all-excluded body', () => {
    const source = parseTemplateSource(
      sampleSource({
        variables: [{ name: 'include', kind: 'boolean', required: true }],
        body: [{ text: 'Only when included.', when: 'include' }],
      }),
    );
    expect(() => renderDocument(source, { include: false })).toThrow(RenderError);
  });
});

describe('escapeHtml', () => {
  it('escapes the five significant characters and nothing else', () => {
    expect(escapeHtml(`&<>"' plain`)).toBe('&amp;&lt;&gt;&quot;&#39; plain');
  });
});
