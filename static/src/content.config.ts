import { defineCollection } from 'astro:content';
import { z } from 'astro/zod';
import { glob } from 'astro/loaders';

// Todo o conteúdo vive em /content na raiz do monorepo (fonte única de verdade).
// Os ids ficam com o prefixo do idioma: "pt/hello-world", "en/hello-world".

const blog = defineCollection({
  loader: glob({ pattern: '**/*.md', base: '../content/blog' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    pubDate: z.coerce.date(),
    tags: z.array(z.string()).default([]),
    draft: z.boolean().default(false),
  }),
});

const projects = defineCollection({
  loader: glob({ pattern: '**/*.md', base: '../content/projects' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    tags: z.array(z.string()).default([]),
    repo: z.string().url().optional(),
    demo: z.string().url().optional(),
    order: z.number().default(99),
  }),
});

const pages = defineCollection({
  loader: glob({ pattern: '**/*.md', base: '../content/pages' }),
  schema: z.object({
    title: z.string(),
  }),
});

export const collections = { blog, projects, pages };
